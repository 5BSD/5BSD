/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2013, Anish Gupta (akgupt3@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#include <sys/cdefs.h>
#include "opt_bhyve_snapshot.h"

#include <sys/param.h>
#include <sys/endian.h>
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

#include <machine/cpufunc.h>
#include <machine/psl.h>
#include <machine/md_var.h>
#include <machine/segments.h>
#include <machine/specialreg.h>
#include <machine/smp.h>
#include <machine/vmm.h>
#include <machine/vmm_instruction_emul.h>
#include <machine/vmm_snapshot.h>
#include <machine/vmparam.h>

#include <dev/vmm/vmm_ktr.h>
#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_startup_entry_owner.h>
#include <dev/vmm/vmm_vm.h>

#include "vmm_lapic.h"
#include "vmm_exception.h"
#include "vmm_stat.h"
#include "vmm_ioport.h"
#include "vatpic.h"
#include "vlapic.h"
#include "vlapic_priv.h"
#include "vpvclock.h"

#include "x86.h"
#include "vmm_x86_startup_backend.h"
#include "vmm_x86_startup_finalizer.h"
#include "vmm_x86_startup_machine.h"
#include "vmcb.h"
#include "nested_svm_aux.h"
#include "nested_svm_bitmap.h"
#include "nested_svm_compose.h"
#include "nested_svm_exit_policy.h"
#include "nested_svm_l2_msr.h"
#include "nested_svm_memory.h"
#include "nested_svm_npt.h"
#include "nested_svm_npt_root.h"
#include "nested_svm_operand.h"
#include "nested_svm_policy.h"
#include "nested_svm_reflect.h"
#include "svm.h"
#include "svm_softc.h"
#include "svm_msr.h"
#include "npt.h"
#include "io/ppt.h"

SYSCTL_DECL(_hw_vmm);
SYSCTL_NODE(_hw_vmm, OID_AUTO, svm, CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    NULL);

SDT_PROBE_DEFINE5(vmm, svm, nested, entry,
    "struct svm_softc *", "int", "uint64_t", "uint64_t", "uint32_t");
SDT_PROBE_DEFINE5(vmm, svm, nested, vmexit,
    "struct svm_softc *", "int", "uint64_t", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE5(vmm, svm, nested, instruction,
    "struct svm_softc *", "int", "uint32_t", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE5(vmm, svm, nested, failure,
    "struct svm_softc *", "int", "int", "uint64_t", "uint32_t");
SDT_PROBE_DEFINE5(vmm, svm, nested, restore,
    "struct svm_softc *", "int", "uint32_t", "uint32_t", "int");
SDT_PROBE_DEFINE5(vmm, svm, nested, npf,
    "struct svm_softc *", "int", "uint64_t", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE5(vmm, svm, exit, nestedfault,
    "struct svm_softc *", "int", "struct vm_exit *", "uint64_t",
    "uint64_t");

/*
 * SVM CPUID function 0x8000_000A, edx bit decoding.
 */
#define AMD_CPUID_SVM_NP		BIT(0)  /* Nested paging or RVI */
#define AMD_CPUID_SVM_LBR		BIT(1)  /* Last branch virtualization */
#define AMD_CPUID_SVM_SVML		BIT(2)  /* SVM lock */
#define AMD_CPUID_SVM_NRIP_SAVE		BIT(3)  /* Next RIP is saved */
#define AMD_CPUID_SVM_TSC_RATE		BIT(4)  /* TSC rate control. */
#define AMD_CPUID_SVM_VMCB_CLEAN	BIT(5)  /* VMCB state caching */
#define AMD_CPUID_SVM_FLUSH_BY_ASID	BIT(6)  /* Flush by ASID */
#define AMD_CPUID_SVM_DECODE_ASSIST	BIT(7)  /* Decode assist */
#define AMD_CPUID_SVM_PAUSE_INC		BIT(10) /* Pause intercept filter. */
#define AMD_CPUID_SVM_PAUSE_FTH		BIT(12) /* Pause filter threshold */
#define	AMD_CPUID_SVM_AVIC		BIT(13)	/* AVIC present */
#define AMD_CPUID_SVM_VNMI		BIT(25) /* Virtual NMI */

#define	VMCB_CACHE_DEFAULT	(VMCB_CACHE_ASID 	|	\
				VMCB_CACHE_IOPM		|	\
				VMCB_CACHE_I		|	\
				VMCB_CACHE_TPR		|	\
				VMCB_CACHE_CR2		|	\
				VMCB_CACHE_CR		|	\
				VMCB_CACHE_DR		|	\
				VMCB_CACHE_DT		|	\
				VMCB_CACHE_SEG		|	\
				VMCB_CACHE_NP)

static uint32_t vmcb_clean = VMCB_CACHE_DEFAULT;
SYSCTL_INT(_hw_vmm_svm, OID_AUTO, vmcb_clean, CTLFLAG_RDTUN, &vmcb_clean,
    0, NULL);

static MALLOC_DEFINE(M_SVM, "svm", "svm");
static MALLOC_DEFINE(M_SVM_VLAPIC, "svm-vlapic", "svm-vlapic");

static uint32_t svm_feature = ~0U;	/* AMD SVM features. */
SYSCTL_UINT(_hw_vmm_svm, OID_AUTO, features, CTLFLAG_RDTUN, &svm_feature, 0,
    "SVM features advertised by CPUID.8000000AH:EDX");

static int disable_npf_assist;
SYSCTL_INT(_hw_vmm_svm, OID_AUTO, disable_npf_assist, CTLFLAG_RWTUN,
    &disable_npf_assist, 0, NULL);

/* Root may opt in at module load to qualify the frozen-target startup path. */
static int kernel_startup_experimental;
SYSCTL_INT(_hw_vmm_svm, OID_AUTO, kernel_startup_experimental,
    CTLFLAG_RDTUN, &kernel_startup_experimental, 0,
    "Enable experimental AMD kernel-owned INIT/SIPI for hardware tests");

/* Require a host opt-in as well as the guest VM_CAP_NESTED_SVM setting. */
static int nested_svm_allowed;
SYSCTL_INT(_hw_vmm_svm, OID_AUTO, nested, CTLFLAG_RDTUN,
    &nested_svm_allowed, 0,
    "Permit explicitly configured guests to use nested SVM");

/* Maximum ASIDs supported by the processor */
static uint32_t nasid;
SYSCTL_UINT(_hw_vmm_svm, OID_AUTO, num_asids, CTLFLAG_RDTUN, &nasid, 0,
    "Number of ASIDs supported by this processor");

/* Current ASID generation for each host cpu */
static struct asid asid[MAXCPU];

/* SVM host state saved area of size 4KB for each physical core. */
static uint8_t *hsave;

static VMM_STAT_AMD(VCPU_EXITINTINFO, "VM exits during event delivery");
static VMM_STAT_AMD(VCPU_INTINFO_INJECTED, "Events pending at VM entry");
static VMM_STAT_AMD(VMEXIT_VINTR, "VM exits due to interrupt window");

static int svm_getdesc(void *vcpui, int reg, struct seg_desc *desc);
static int svm_setdesc(void *vcpui, int reg, struct seg_desc *desc);
static int svm_setreg(void *vcpui, int ident, uint64_t val);
static int svm_getreg(void *vcpui, int ident, uint64_t *val);
static int svm_nested_l2_reflect(struct svm_vcpu *vcpu);
static int svm_nested_l2_synthetic_exception(struct svm_vcpu *vcpu,
    uint8_t vector, bool error_code_valid, uint32_t error_code);
static __inline int
flush_by_asid(void)
{

	return (svm_feature & AMD_CPUID_SVM_FLUSH_BY_ASID);
}

static __inline int
decode_assist(void)
{

	return (svm_feature & AMD_CPUID_SVM_DECODE_ASSIST);
}

static void
svm_disable(void *arg __unused)
{
	uint64_t efer;

	efer = rdmsr(MSR_EFER);
	efer &= ~EFER_SVM;
	wrmsr(MSR_EFER, efer);
}

/*
 * Disable SVM on all CPUs.
 */
static int
svm_modcleanup(void)
{

	smp_rendezvous(NULL, svm_disable, NULL, NULL);

	if (hsave != NULL)
		kmem_free(hsave, (mp_maxid + 1) * PAGE_SIZE);

	return (0);
}

/*
 * Verify that all the features required by bhyve are available.
 */
static int
check_svm_features(void)
{
	u_int regs[4];

	/* CPUID Fn8000_000A is for SVM */
	do_cpuid(0x8000000A, regs);
	svm_feature &= regs[3];

	/*
	 * The number of ASIDs can be configured to be less than what is
	 * supported by the hardware but not more.
	 */
	if (nasid == 0 || nasid > regs[1])
		nasid = regs[1];
	KASSERT(nasid > 1, ("Insufficient ASIDs for guests: %#x", nasid));

	/* bhyve requires the Nested Paging feature */
	if (!(svm_feature & AMD_CPUID_SVM_NP)) {
		printf("SVM: Nested Paging feature not available.\n");
		return (ENXIO);
	}

	/* bhyve requires the NRIP Save feature */
	if (!(svm_feature & AMD_CPUID_SVM_NRIP_SAVE)) {
		printf("SVM: NRIP Save feature not available.\n");
		return (ENXIO);
	}

	return (0);
}

static void
svm_enable(void *arg __unused)
{
	uint64_t efer;

	efer = rdmsr(MSR_EFER);
	efer |= EFER_SVM;
	wrmsr(MSR_EFER, efer);

	wrmsr(MSR_VM_HSAVE_PA, vtophys(&hsave[curcpu * PAGE_SIZE]));
}

/*
 * Return 1 if SVM is enabled on this processor and 0 otherwise.
 */
static int
svm_available(void)
{
	uint64_t msr;

	/* Section 15.4 Enabling SVM from APM2. */
	if ((amd_feature2 & AMDID2_SVM) == 0) {
		printf("SVM: not available.\n");
		return (0);
	}

	msr = rdmsr(MSR_VM_CR);
	if ((msr & VM_CR_SVMDIS) != 0) {
		printf("SVM: disabled by BIOS.\n");
		return (0);
	}

	return (1);
}

static int
svm_modinit(int ipinum)
{
	int error, cpu;

	if (!svm_available())
		return (ENXIO);

	error = check_svm_features();
	if (error)
		return (error);

	vmcb_clean &= VMCB_CACHE_DEFAULT;

	for (cpu = 0; cpu < MAXCPU; cpu++) {
		/*
		 * Initialize the host ASIDs to their "highest" valid values.
		 *
		 * The next ASID allocation will rollover both 'gen' and 'num'
		 * and start off the sequence at {1,1}.
		 */
		asid[cpu].gen = ~0UL;
		asid[cpu].num = nasid - 1;
	}

	svm_msr_init();
	svm_npt_init(ipinum);

	/* Enable SVM on all CPUs */
	hsave = kmem_malloc((mp_maxid + 1) * PAGE_SIZE, M_WAITOK | M_ZERO);
	smp_rendezvous(NULL, svm_enable, NULL, NULL);

	return (0);
}

static void
svm_modsuspend(void)
{
}

static void
svm_modresume(void)
{

	svm_enable(NULL);
}

void
svm_set_tsc_offset(struct svm_vcpu *vcpu, uint64_t offset)
{
	struct vmcb_ctrl *ctrl;

	ctrl = svm_get_vmcb_ctrl(vcpu);
	ctrl->tsc_offset = offset;
	if (vcpu->nested_active) {
		vcpu->nested_vmcb02->ctrl.tsc_offset = offset +
		    vcpu->nested_vmcb12->ctrl.tsc_offset;
		vcpu->nested_vmcb02->ctrl.vmcb_clean = 0;
	}

	svm_set_dirty(vcpu, VMCB_CACHE_I);
	SVM_CTR1(vcpu, "tsc offset changed to %#lx", offset);

	vm_set_tsc_offset(vcpu->vcpu, offset);
}

/* Pentium compatible MSRs */
#define MSR_PENTIUM_START 	0
#define MSR_PENTIUM_END 	0x1FFF
/* AMD 6th generation and Intel compatible MSRs */
#define MSR_AMD6TH_START 	0xC0000000UL
#define MSR_AMD6TH_END 		0xC0001FFFUL
/* AMD 7th and 8th generation compatible MSRs */
#define MSR_AMD7TH_START 	0xC0010000UL
#define MSR_AMD7TH_END 		0xC0011FFFUL

static void
svm_get_cs_info(struct vmcb *vmcb, struct vm_guest_paging *paging, int *cs_d,
    uint64_t *base)
{
	struct vmcb_segment seg;
	int error __diagused;

	error = vmcb_seg(vmcb, VM_REG_GUEST_CS, &seg);
	KASSERT(error == 0, ("%s: vmcb_seg error %d", __func__, error));

	switch (paging->cpu_mode) {
	case CPU_MODE_REAL:
		*base = seg.base;
		*cs_d = 0;
		break;
	case CPU_MODE_PROTECTED:
	case CPU_MODE_COMPATIBILITY:
		*cs_d = !!(seg.attrib & VMCB_CS_ATTRIB_D);
		*base = seg.base;
		break;
	default:
		*base = 0;
		*cs_d = 0;
		break;
	}
}

/*
 * Get the index and bit position for a MSR in permission bitmap.
 * Two bits are used for each MSR: lower bit for read and higher bit for write.
 */
static int
svm_msr_index(uint64_t msr, int *index, int *bit)
{
	uint32_t base, off;

	*index = -1;
	*bit = (msr % 4) * 2;
	base = 0;

	if (msr >= MSR_PENTIUM_START && msr <= MSR_PENTIUM_END) {
		*index = msr / 4;
		return (0);
	}

	base += (MSR_PENTIUM_END - MSR_PENTIUM_START + 1);
	if (msr >= MSR_AMD6TH_START && msr <= MSR_AMD6TH_END) {
		off = (msr - MSR_AMD6TH_START);
		*index = (off + base) / 4;
		return (0);
	}

	base += (MSR_AMD6TH_END - MSR_AMD6TH_START + 1);
	if (msr >= MSR_AMD7TH_START && msr <= MSR_AMD7TH_END) {
		off = (msr - MSR_AMD7TH_START);
		*index = (off + base) / 4;
		return (0);
	}

	return (EINVAL);
}

/*
 * Allow vcpu to read or write the 'msr' without trapping into the hypervisor.
 */
static void
svm_msr_perm(uint8_t *perm_bitmap, uint64_t msr, bool read, bool write)
{
	int index, bit, error __diagused;

	error = svm_msr_index(msr, &index, &bit);
	KASSERT(error == 0, ("%s: invalid msr %#lx", __func__, msr));
	KASSERT(index >= 0 && index < SVM_MSR_BITMAP_SIZE,
	    ("%s: invalid index %d for msr %#lx", __func__, index, msr));
	KASSERT(bit >= 0 && bit <= 6, ("%s: invalid bit position %d "
	    "msr %#lx", __func__, bit, msr));

	if (read)
		perm_bitmap[index] &= ~(1UL << bit);

	if (write)
		perm_bitmap[index] &= ~(2UL << bit);
}

static void
svm_msr_rw_ok(uint8_t *perm_bitmap, uint64_t msr)
{

	svm_msr_perm(perm_bitmap, msr, true, true);
}

static void
svm_msr_rd_ok(uint8_t *perm_bitmap, uint64_t msr)
{

	svm_msr_perm(perm_bitmap, msr, true, false);
}

static __inline int
svm_get_intercept(struct svm_vcpu *vcpu, int idx, uint32_t bitmask)
{
	struct vmcb_ctrl *ctrl;

	KASSERT(idx >=0 && idx < 5, ("invalid intercept index %d", idx));

	ctrl = svm_get_vmcb_ctrl(vcpu);
	return (ctrl->intercept[idx] & bitmask ? 1 : 0);
}

static __inline void
svm_set_intercept(struct svm_vcpu *vcpu, int idx, uint32_t bitmask, int enabled)
{
	struct vmcb_ctrl *ctrl;
	uint32_t oldval;

	KASSERT(idx >=0 && idx < 5, ("invalid intercept index %d", idx));

	ctrl = svm_get_vmcb_ctrl(vcpu);
	oldval = ctrl->intercept[idx];

	if (enabled)
		ctrl->intercept[idx] |= bitmask;
	else
		ctrl->intercept[idx] &= ~bitmask;

	if (ctrl->intercept[idx] != oldval) {
		svm_set_dirty(vcpu, VMCB_CACHE_I);
		SVM_CTR3(vcpu, "intercept[%d] modified from %#x to %#x", idx,
		    oldval, ctrl->intercept[idx]);
	}
}

/* Keep a live VMCB02 in sync when an L0 exit capability changes. */
static void
svm_setcap_intercept(struct svm_vcpu *vcpu, int idx, uint32_t bitmask,
    int enabled)
{
	uint32_t l1_bits;

	svm_set_intercept(vcpu, idx, bitmask, enabled);
	if (!vcpu->nested_active)
		return;
	l1_bits = vcpu->nested_vmcb12->ctrl.intercept[idx];
	if (enabled || (l1_bits & bitmask) != 0)
		vcpu->nested_vmcb02->ctrl.intercept[idx] |= bitmask;
	else
		vcpu->nested_vmcb02->ctrl.intercept[idx] &= ~bitmask;
}

static __inline void
svm_disable_intercept(struct svm_vcpu *vcpu, int off, uint32_t bitmask)
{

	svm_set_intercept(vcpu, off, bitmask, 0);
}

static __inline void
svm_enable_intercept(struct svm_vcpu *vcpu, int off, uint32_t bitmask)
{

	svm_set_intercept(vcpu, off, bitmask, 1);
}

static void
vmcb_init(struct svm_softc *sc, struct svm_vcpu *vcpu, uint64_t iopm_base_pa,
    uint64_t msrpm_base_pa, uint64_t np_pml4)
{
	struct vmcb_ctrl *ctrl;
	struct vmcb_state *state;
	uint32_t mask;
	int n;

	ctrl = svm_get_vmcb_ctrl(vcpu);
	state = svm_get_vmcb_state(vcpu);

	ctrl->iopm_base_pa = iopm_base_pa;
	ctrl->msrpm_base_pa = msrpm_base_pa;

	/* Enable nested paging */
	ctrl->np_enable = 1;
	ctrl->n_cr3 = np_pml4;

	/*
	 * Intercept accesses to the control registers that are not shadowed
	 * in the VMCB - i.e. all except cr0, cr2, cr3, cr4 and cr8.
	 */
	for (n = 0; n < 16; n++) {
		mask = (BIT(n) << 16) | BIT(n);
		if (n == 0 || n == 2 || n == 3 || n == 4 || n == 8)
			svm_disable_intercept(vcpu, VMCB_CR_INTCPT, mask);
		else
			svm_enable_intercept(vcpu, VMCB_CR_INTCPT, mask);
	}

	/*
	 * Intercept everything when tracing guest exceptions otherwise
	 * just intercept machine check exception.
	 */
	if (vcpu_trace_exceptions(vcpu->vcpu)) {
		for (n = 0; n < 32; n++) {
			/*
			 * Skip unimplemented vectors in the exception bitmap.
			 */
			if (n == 2 || n == 9) {
				continue;
			}
			svm_enable_intercept(vcpu, VMCB_EXC_INTCPT, BIT(n));
		}
	} else {
		svm_enable_intercept(vcpu, VMCB_EXC_INTCPT, BIT(IDT_MC));
	}

	/* Intercept various events (for e.g. I/O, MSR and CPUID accesses) */
	svm_enable_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_IO);
	svm_enable_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_MSR);
	svm_enable_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_CPUID);
	svm_enable_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_INTR);
	svm_enable_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_INIT);
	svm_enable_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_NMI);
	svm_enable_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_SMI);
	svm_enable_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_SHUTDOWN);
	svm_enable_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_FERR_FREEZE);
	svm_enable_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_INVD);
	svm_enable_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_INVLPGA);

	svm_enable_intercept(vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_MONITOR);
	svm_enable_intercept(vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_MWAIT);

	/*
	 * Intercept SVM instructions since AMD enables them in guests otherwise.
	 * Non-intercepted VMMCALL causes #UD, skip it.
	 */
	svm_enable_intercept(vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_VMLOAD);
	svm_enable_intercept(vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_VMSAVE);
	svm_enable_intercept(vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_STGI);
	svm_enable_intercept(vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_CLGI);
	svm_enable_intercept(vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_SKINIT);
	svm_enable_intercept(vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_ICEBP);
	if (vcpu_trap_wbinvd(vcpu->vcpu)) {
		svm_enable_intercept(vcpu, VMCB_CTRL2_INTCPT,
		    VMCB_INTCPT_WBINVD);
	}

	/*
	 * From section "Canonicalization and Consistency Checks" in APMv2
	 * the VMRUN intercept bit must be set to pass the consistency check.
	 */
	svm_enable_intercept(vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_VMRUN);

	/*
	 * The ASID will be set to a non-zero value just before VMRUN.
	 */
	ctrl->asid = 0;

	/*
	 * Section 15.21.1, Interrupt Masking in EFLAGS
	 * Section 15.21.2, Virtualizing APIC.TPR
	 *
	 * This must be set for %rflag and %cr8 isolation of guest and host.
	 */
	ctrl->v_intr_masking = 1;

	/* Enable Last Branch Record aka LBR for debugging */
	ctrl->lbr_virt_en = 1;
	state->dbgctl = BIT(0);

	/* EFER_SVM must always be set when the guest is executing */
	state->efer = EFER_SVM;

	/* Set up the PAT to power-on state */
	state->g_pat = PAT_VALUE(0, PAT_WRITE_BACK)	|
	    PAT_VALUE(1, PAT_WRITE_THROUGH)	|
	    PAT_VALUE(2, PAT_UNCACHED)		|
	    PAT_VALUE(3, PAT_UNCACHEABLE)	|
	    PAT_VALUE(4, PAT_WRITE_BACK)	|
	    PAT_VALUE(5, PAT_WRITE_THROUGH)	|
	    PAT_VALUE(6, PAT_UNCACHED)		|
	    PAT_VALUE(7, PAT_UNCACHEABLE);

	/* Set up DR6/7 to power-on state */
	state->dr6 = DBREG_DR6_RESERVED1;
	state->dr7 = DBREG_DR7_RESERVED1;
}

/*
 * Initialize a virtual machine.
 */
static void *
svm_init(struct vm *vm, pmap_t pmap)
{
	struct svm_softc *svm_sc;

	svm_sc = malloc(sizeof (*svm_sc), M_SVM, M_WAITOK | M_ZERO);

	svm_sc->msr_bitmap = contigmalloc(SVM_MSR_BITMAP_SIZE, M_SVM,
	    M_WAITOK, 0, ~(vm_paddr_t)0, PAGE_SIZE, 0);
	if (svm_sc->msr_bitmap == NULL)
		panic("contigmalloc of SVM MSR bitmap failed");
	svm_sc->iopm_bitmap = contigmalloc(SVM_IO_BITMAP_SIZE, M_SVM,
	    M_WAITOK, 0, ~(vm_paddr_t)0, PAGE_SIZE, 0);
	if (svm_sc->iopm_bitmap == NULL)
		panic("contigmalloc of SVM IO bitmap failed");
	svm_sc->nested_msr_bitmap = contigmalloc(SVM_MSR_BITMAP_SIZE, M_SVM,
	    M_WAITOK, 0, ~(vm_paddr_t)0, PAGE_SIZE, 0);
	if (svm_sc->nested_msr_bitmap == NULL)
		panic("contigmalloc of nested SVM MSR bitmap failed");

	svm_sc->vm = vm;
	svm_sc->nptp = vtophys(pmap->pm_pmltop);

	/*
	 * Intercept read and write accesses to all MSRs.
	 */
	memset(svm_sc->msr_bitmap, 0xFF, SVM_MSR_BITMAP_SIZE);

	/*
	 * Access to the following MSRs is redirected to the VMCB when the
	 * guest is executing. Therefore it is safe to allow the guest to
	 * read/write these MSRs directly without hypervisor involvement.
	 */
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_GSBASE);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_FSBASE);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_KGSBASE);

	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_STAR);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_LSTAR);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_CSTAR);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_SF_MASK);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_SYSENTER_CS_MSR);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_SYSENTER_ESP_MSR);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_SYSENTER_EIP_MSR);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_PAT);

	svm_msr_rd_ok(svm_sc->msr_bitmap, MSR_TSC);

	/*
	 * EFER.SVME is required by the hardware VMCB but is not part of the
	 * ordinary guest CPU model.  Intercept reads as well as writes so the
	 * guest cannot observe the physical bit behind the SVM CPUID mask.
	 */

	/* Intercept access to all I/O ports. */
	memset(svm_sc->iopm_bitmap, 0xFF, SVM_IO_BITMAP_SIZE);
	memset(svm_sc->nested_msr_bitmap, 0xFF, SVM_MSR_BITMAP_SIZE);

	return (svm_sc);
}

static void *
svm_vcpu_init(void *vmi, struct vcpu *vcpu1, int vcpuid)
{
	struct svm_softc *sc = vmi;
	struct svm_vcpu *vcpu;

	vcpu = malloc(sizeof(*vcpu), M_SVM, M_WAITOK | M_ZERO);
	vcpu->sc = sc;
	vcpu->vcpu = vcpu1;
	vcpu->vcpuid = vcpuid;
	vcpu->vmcb = malloc_aligned(sizeof(struct vmcb), PAGE_SIZE, M_SVM,
	    M_WAITOK | M_ZERO);
	vcpu->snapshot_vmcb = malloc_aligned(sizeof(struct vmcb), PAGE_SIZE,
	    M_SVM, M_WAITOK | M_ZERO);
	vcpu->nested_vmcb12 = malloc_aligned(sizeof(struct vmcb), PAGE_SIZE,
	    M_SVM, M_WAITOK | M_ZERO);
	vcpu->nested_vmcb02 = malloc_aligned(sizeof(struct vmcb), PAGE_SIZE,
	    M_SVM, M_WAITOK | M_ZERO);
	vcpu->nextrip = ~0;
	vcpu->lastcpu = NOCPU;
	svm_nested_msr_state_init(&vcpu->nested_msr);
	vcpu->nested_gif = true;
	vcpu->vmcb_pa = vtophys(vcpu->vmcb);
	vmcb_init(sc, vcpu, vtophys(sc->iopm_bitmap), vtophys(sc->msr_bitmap),
	    sc->nptp);
	svm_msr_guest_init(sc, vcpu);
	return (vcpu);
}

/*
 * Collateral for a generic SVM VM-exit.
 */
static void
vm_exit_svm(struct vm_exit *vme, uint64_t code, uint64_t info1, uint64_t info2)
{

	vme->exitcode = VM_EXITCODE_SVM;
	vme->u.svm.exitcode = code;
	vme->u.svm.exitinfo1 = info1;
	vme->u.svm.exitinfo2 = info2;
}

static int
svm_cpl(struct vmcb_state *state)
{

	/*
	 * From APMv2:
	 *   "Retrieve the CPL from the CPL field in the VMCB, not
	 *    from any segment DPL"
	 */
	return (state->cpl);
}

static enum vm_cpu_mode
svm_vcpu_mode(struct vmcb *vmcb)
{
	struct vmcb_segment seg;
	struct vmcb_state *state;
	int error __diagused;

	state = &vmcb->state;

	if (state->efer & EFER_LMA) {
		error = vmcb_seg(vmcb, VM_REG_GUEST_CS, &seg);
		KASSERT(error == 0, ("%s: vmcb_seg(cs) error %d", __func__,
		    error));

		/*
		 * Section 4.8.1 for APM2, check if Code Segment has
		 * Long attribute set in descriptor.
		 */
		if (seg.attrib & VMCB_CS_ATTRIB_L)
			return (CPU_MODE_64BIT);
		else
			return (CPU_MODE_COMPATIBILITY);
	} else  if (state->cr0 & CR0_PE) {
		return (CPU_MODE_PROTECTED);
	} else {
		return (CPU_MODE_REAL);
	}
}

static enum vm_paging_mode
svm_paging_mode(uint64_t cr0, uint64_t cr4, uint64_t efer)
{

	if ((cr0 & CR0_PG) == 0)
		return (PAGING_MODE_FLAT);
	if ((cr4 & CR4_PAE) == 0)
		return (PAGING_MODE_32);
	if (efer & EFER_LME)
		return (PAGING_MODE_64);
	else
		return (PAGING_MODE_PAE);
}

/*
 * ins/outs utility routines
 */
static uint64_t
svm_inout_str_index(struct svm_regctx *regs, int in)
{
	uint64_t val;

	val = in ? regs->sctx_rdi : regs->sctx_rsi;

	return (val);
}

static uint64_t
svm_inout_str_count(struct svm_regctx *regs, int rep)
{
	uint64_t val;

	val = rep ? regs->sctx_rcx : 1;

	return (val);
}

static void
svm_inout_str_seginfo(struct svm_vcpu *vcpu, struct vmcb *vmcb,
    int64_t info1, int in, struct vm_inout_str *vis)
{
	int error __diagused, s;

	if (in) {
		vis->seg_name = VM_REG_GUEST_ES;
	} else if (decode_assist()) {
		/*
		 * The effective segment number in EXITINFO1[12:10] is populated
		 * only if the processor has the DecodeAssist capability.
		 *
		 * XXX this is not specified explicitly in APMv2 but can be
		 * verified empirically.
		 */
		s = (info1 >> 10) & 0x7;

		/* The segment field has standard encoding */
		vis->seg_name = vm_segment_name(s);
	} else {
		/*
		 * The segment register need to be manually decoded by fetching
		 * the instructions near ip. However, we are unable to fetch it
		 * while the interrupts are disabled. Therefore, we leave the
		 * value unset until the generic ins/outs handler runs.
		 */
		vis->seg_name = VM_REG_LAST;
		svm_get_cs_info(vmcb, &vis->paging, &vis->cs_d,
		    &vis->cs_base);
		return;
	}

	error = svm_getdesc(vcpu, vis->seg_name, &vis->seg_desc);
	KASSERT(error == 0, ("%s: svm_getdesc error %d", __func__, error));
}

static int
svm_inout_str_addrsize(uint64_t info1)
{
        uint32_t size;

        size = (info1 >> 7) & 0x7;
        switch (size) {
        case 1:
                return (2);     /* 16 bit */
        case 2:
                return (4);     /* 32 bit */
        case 4:
                return (8);     /* 64 bit */
        default:
                panic("%s: invalid size encoding %d", __func__, size);
        }
}

static void
svm_paging_info(struct vmcb *vmcb, struct vm_guest_paging *paging)
{
	struct vmcb_state *state;

	state = &vmcb->state;
	paging->cr3 = state->cr3;
	paging->cpl = svm_cpl(state);
	paging->cpu_mode = svm_vcpu_mode(vmcb);
	paging->paging_mode = svm_paging_mode(state->cr0, state->cr4,
	    state->efer);
}

#define	UNHANDLED 0

/*
 * Handle guest I/O intercept.
 */
static int
svm_handle_io(struct svm_vcpu *vcpu, struct vmcb *vmcb,
    struct vm_exit *vmexit)
{
	struct vmcb_ctrl *ctrl;
	struct vmcb_state *state;
	struct svm_regctx *regs;
	struct vm_inout_str *vis;
	uint64_t info1;
	int inout_string;

	state = &vmcb->state;
	ctrl  = &vmcb->ctrl;
	regs  = svm_get_guest_regctx(vcpu);

	info1 = ctrl->exitinfo1;
	inout_string = info1 & BIT(2) ? 1 : 0;

	vmexit->exitcode 	= VM_EXITCODE_INOUT;
	vmexit->u.inout.in 	= (info1 & BIT(0)) ? 1 : 0;
	vmexit->u.inout.string 	= inout_string;
	vmexit->u.inout.rep 	= (info1 & BIT(3)) ? 1 : 0;
	vmexit->u.inout.bytes 	= (info1 >> 4) & 0x7;
	vmexit->u.inout.port 	= (uint16_t)(info1 >> 16);
	vmexit->u.inout.eax 	= (uint32_t)(state->rax);

	if (inout_string) {
		vmexit->exitcode = VM_EXITCODE_INOUT_STR;
		vis = &vmexit->u.inout_str;
		svm_paging_info(vmcb, &vis->paging);
		vis->rflags = state->rflags;
		vis->cr0 = state->cr0;
		vis->index = svm_inout_str_index(regs, vmexit->u.inout.in);
		vis->count = svm_inout_str_count(regs, vmexit->u.inout.rep);
		vis->addrsize = svm_inout_str_addrsize(info1);
		vis->cs_d = 0;
		vis->cs_base = 0;
		svm_inout_str_seginfo(vcpu, vmcb, info1,
		    vmexit->u.inout.in, vis);
	}

	return (UNHANDLED);
}

static int
npf_fault_type(uint64_t exitinfo1)
{

	if (exitinfo1 & VMCB_NPF_INFO1_W)
		return (VM_PROT_WRITE);
	else if (exitinfo1 & VMCB_NPF_INFO1_ID)
		return (VM_PROT_EXECUTE);
	else
		return (VM_PROT_READ);
}

static bool
svm_npf_emul_fault(uint64_t exitinfo1)
{

	if (exitinfo1 & VMCB_NPF_INFO1_ID) {
		return (false);
	}

	if (exitinfo1 & VMCB_NPF_INFO1_GPT) {
		return (false);
	}

	if ((exitinfo1 & VMCB_NPF_INFO1_GPA) == 0) {
		return (false);
	}

	return (true);
}

static void
svm_handle_inst_emul(struct vmcb *vmcb, uint64_t gpa, struct vm_exit *vmexit)
{
	struct vm_guest_paging *paging;
	struct vmcb_ctrl *ctrl;
	const char *inst_bytes;
	int inst_len;

	ctrl = &vmcb->ctrl;
	paging = &vmexit->u.inst_emul.paging;

	vmexit->exitcode = VM_EXITCODE_INST_EMUL;
	vmexit->u.inst_emul.gpa = gpa;
	vmexit->u.inst_emul.gla = VIE_INVALID_GLA;
	svm_paging_info(vmcb, paging);

	svm_get_cs_info(vmcb, paging, &vmexit->u.inst_emul.cs_d,
	    &vmexit->u.inst_emul.cs_base);

	/*
	 * Copy the instruction bytes into 'vie' if available.
	 */
	if (decode_assist() && !disable_npf_assist) {
		inst_len = ctrl->inst_len;
		inst_bytes = (const char *)(const void *)ctrl->inst_bytes;
	} else {
		inst_len = 0;
		inst_bytes = NULL;
	}
	vie_init(&vmexit->u.inst_emul.vie, inst_bytes, inst_len);
}

#ifdef KTR
static const char *
intrtype_to_str(int intr_type)
{
	switch (intr_type) {
	case VMCB_EVENTINJ_TYPE_INTR:
		return ("hwintr");
	case VMCB_EVENTINJ_TYPE_NMI:
		return ("nmi");
	case VMCB_EVENTINJ_TYPE_INTn:
		return ("swintr");
	case VMCB_EVENTINJ_TYPE_EXCEPTION:
		return ("exception");
	default:
		panic("%s: unknown intr_type %d", __func__, intr_type);
	}
}
#endif

/*
 * Inject an event to vcpu as described in section 15.20, "Event injection".
 */
static void
svm_eventinject_to_vmcb(struct svm_vcpu *vcpu, struct vmcb_ctrl *ctrl,
    int intr_type, int vector, uint32_t error, bool ec_valid)
{

	KASSERT((ctrl->eventinj & VMCB_EVENTINJ_VALID) == 0,
	    ("%s: event already pending %#lx", __func__, ctrl->eventinj));

	KASSERT(vector >=0 && vector <= 255, ("%s: invalid vector %d",
	    __func__, vector));

	switch (intr_type) {
	case VMCB_EVENTINJ_TYPE_INTR:
	case VMCB_EVENTINJ_TYPE_NMI:
	case VMCB_EVENTINJ_TYPE_INTn:
		break;
	case VMCB_EVENTINJ_TYPE_EXCEPTION:
		if (vector >= 0 && vector <= 31 && vector != 2)
			break;
		/* FALLTHROUGH */
	default:
		panic("%s: invalid intr_type/vector: %d/%d", __func__,
		    intr_type, vector);
	}
	ctrl->eventinj = vector | (intr_type << 8) | VMCB_EVENTINJ_VALID;
	if (ec_valid) {
		ctrl->eventinj |= VMCB_EVENTINJ_EC_VALID;
		ctrl->eventinj |= (uint64_t)error << 32;
		SVM_CTR3(vcpu, "Injecting %s at vector %d errcode %#x",
		    intrtype_to_str(intr_type), vector, error);
	} else {
		SVM_CTR2(vcpu, "Injecting %s at vector %d",
		    intrtype_to_str(intr_type), vector);
	}
}

static void
svm_eventinject(struct svm_vcpu *vcpu, int intr_type, int vector,
    uint32_t error, bool ec_valid)
{

	svm_eventinject_to_vmcb(vcpu, svm_get_vmcb_ctrl(vcpu), intr_type,
	    vector, error, ec_valid);
}

static void
svm_update_virqinfo(struct svm_vcpu *vcpu)
{
	struct vlapic *vlapic;
	struct vmcb_ctrl *ctrl;

	vlapic = vm_lapic(vcpu->vcpu);
	ctrl = svm_get_vmcb_ctrl(vcpu);

	/* Update %cr8 in the emulated vlapic */
	vlapic_set_cr8(vlapic, ctrl->v_tpr);

	/* Virtual interrupt injection is not used. */
	KASSERT(ctrl->v_intr_vector == 0, ("%s: invalid "
	    "v_intr_vector %d", __func__, ctrl->v_intr_vector));
}

static void
svm_save_intinfo(struct svm_softc *svm_sc, struct svm_vcpu *vcpu)
{
	struct vmcb_ctrl *ctrl;
	uint64_t intinfo;

	ctrl = svm_get_vmcb_ctrl(vcpu);
	intinfo = ctrl->exitintinfo;
	if (!VMCB_EXITINTINFO_VALID(intinfo))
		return;

	/*
	 * From APMv2, Section "Intercepts during IDT interrupt delivery"
	 *
	 * If a #VMEXIT happened during event delivery then record the event
	 * that was being delivered.
	 */
	SVM_CTR2(vcpu, "SVM:Pending INTINFO(0x%lx), vector=%d.\n", intinfo,
	    VMCB_EXITINTINFO_VECTOR(intinfo));
	vmm_stat_incr(vcpu->vcpu, VCPU_EXITINTINFO, 1);
	vm_exit_intinfo(vcpu->vcpu, intinfo);
}

#ifdef INVARIANTS
static __inline int
vintr_intercept_enabled(struct svm_vcpu *vcpu)
{

	return (svm_get_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_VINTR));
}
#endif

static __inline void
enable_intr_window_exiting(struct svm_vcpu *vcpu)
{
	struct vmcb_ctrl *ctrl;

	ctrl = svm_get_vmcb_ctrl(vcpu);

	if (ctrl->v_irq && ctrl->v_intr_vector == 0) {
		KASSERT(ctrl->v_ign_tpr, ("%s: invalid v_ign_tpr", __func__));
		KASSERT(vintr_intercept_enabled(vcpu),
		    ("%s: vintr intercept should be enabled", __func__));
		return;
	}

	SVM_CTR0(vcpu, "Enable intr window exiting");
	ctrl->v_irq = 1;
	ctrl->v_ign_tpr = 1;
	ctrl->v_intr_vector = 0;
	svm_set_dirty(vcpu, VMCB_CACHE_TPR);
	svm_enable_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_VINTR);
}

static __inline void
disable_intr_window_exiting(struct svm_vcpu *vcpu)
{
	struct vmcb_ctrl *ctrl;

	ctrl = svm_get_vmcb_ctrl(vcpu);

	if (!ctrl->v_irq && ctrl->v_intr_vector == 0) {
		KASSERT(!vintr_intercept_enabled(vcpu),
		    ("%s: vintr intercept should be disabled", __func__));
		return;
	}

	SVM_CTR0(vcpu, "Disable intr window exiting");
	ctrl->v_irq = 0;
	ctrl->v_intr_vector = 0;
	svm_set_dirty(vcpu, VMCB_CACHE_TPR);
	svm_disable_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_VINTR);
}

static int
svm_modify_intr_shadow(struct svm_vcpu *vcpu, uint64_t val)
{
	struct vmcb_ctrl *ctrl;
	int oldval, newval;

	ctrl = svm_get_vmcb_ctrl(vcpu);
	oldval = ctrl->intr_shadow;
	newval = val ? 1 : 0;
	if (newval != oldval) {
		ctrl->intr_shadow = newval;
		SVM_CTR1(vcpu, "Setting intr_shadow to %d", newval);
	}
	return (0);
}

static int
svm_get_intr_shadow(struct svm_vcpu *vcpu, uint64_t *val)
{
	struct vmcb_ctrl *ctrl;

	ctrl = svm_get_vmcb_ctrl(vcpu);
	*val = ctrl->intr_shadow;
	return (0);
}

/*
 * Once an NMI is injected it blocks delivery of further NMIs until the handler
 * executes an IRET. The IRET intercept is enabled when an NMI is injected to
 * to track when the vcpu is done handling the NMI.
 */
static int
nmi_blocked(struct svm_vcpu *vcpu)
{
	int blocked;

	blocked = svm_get_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_IRET);
	return (blocked);
}

static void
enable_nmi_blocking(struct svm_vcpu *vcpu)
{

	KASSERT(!nmi_blocked(vcpu), ("vNMI already blocked"));
	SVM_CTR0(vcpu, "vNMI blocking enabled");
	svm_enable_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_IRET);
}

static void
clear_nmi_blocking(struct svm_vcpu *vcpu)
{
	int error __diagused;

	KASSERT(nmi_blocked(vcpu), ("vNMI already unblocked"));
	SVM_CTR0(vcpu, "vNMI blocking cleared");
	/*
	 * When the IRET intercept is cleared the vcpu will attempt to execute
	 * the "iret" when it runs next. However, it is possible to inject
	 * another NMI into the vcpu before the "iret" has actually executed.
	 *
	 * For e.g. if the "iret" encounters a #NPF when accessing the stack
	 * it will trap back into the hypervisor. If an NMI is pending for
	 * the vcpu it will be injected into the guest.
	 *
	 * XXX this needs to be fixed
	 */
	svm_disable_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_IRET);

	/*
	 * Set 'intr_shadow' to prevent an NMI from being injected on the
	 * immediate VMRUN.
	 */
	error = svm_modify_intr_shadow(vcpu, 1);
	KASSERT(!error, ("%s: error %d setting intr_shadow", __func__, error));
}

#define	EFER_MBZ_BITS	0xFFFFFFFFFFFF0200UL

static int
svm_write_efer(struct svm_softc *sc, struct svm_vcpu *vcpu, uint64_t newval,
    bool *retu)
{
	struct vm_exit *vme;
	struct vmcb_state *state;
	uint64_t changed, lma, oldval;
	int error __diagused;

	state = svm_get_vmcb_state(vcpu);

	oldval = svm_nested_msr_efer_read(&vcpu->nested_msr, state->efer);
	SVM_CTR2(vcpu, "wrmsr(efer) %#lx/%#lx", oldval, newval);

	newval &= ~0xFE;		/* clear the Read-As-Zero (RAZ) bits */
	changed = oldval ^ newval;

	if (newval & EFER_MBZ_BITS)
		goto gpf;
	if (!svm_nested_msr_efer_write_allowed(&vcpu->nested_msr,
	    newval))
		goto gpf;

	/* APMv2 Table 14-5 "Long-Mode Consistency Checks" */
	if (changed & EFER_LME) {
		if (state->cr0 & CR0_PG)
			goto gpf;
	}

	/* EFER.LMA = EFER.LME & CR0.PG */
	if ((newval & EFER_LME) != 0 && (state->cr0 & CR0_PG) != 0)
		lma = EFER_LMA;
	else
		lma = 0;

	if ((newval & EFER_LMA) != lma)
		goto gpf;

	if (newval & EFER_NXE) {
		if (!vm_cpuid_capability(vcpu->vcpu, VCC_NO_EXECUTE))
			goto gpf;
	}

	/*
	 * XXX bhyve does not enforce segment limits in 64-bit mode. Until
	 * this is fixed flag guest attempt to set EFER_LMSLE as an error.
	 */
	if (newval & EFER_LMSLE) {
		vme = vm_exitinfo(vcpu->vcpu);
		vm_exit_svm(vme, VMCB_EXIT_MSR, 1, 0);
		*retu = true;
		return (0);
	}

	if (newval & EFER_FFXSR) {
		if (!vm_cpuid_capability(vcpu->vcpu, VCC_FFXSR))
			goto gpf;
	}

	if (newval & EFER_TCE) {
		if (!vm_cpuid_capability(vcpu->vcpu, VCC_TCE))
			goto gpf;
	}

	error = svm_setreg(vcpu, VM_REG_GUEST_EFER, newval);
	KASSERT(error == 0, ("%s: error %d updating efer", __func__, error));
	return (0);
gpf:
	vm_inject_gp(vcpu->vcpu);
	return (0);
}

static int
emulate_wrmsr(struct svm_softc *sc, struct svm_vcpu *vcpu, u_int num,
    uint64_t val, bool *retu)
{
	int error;

	if (lapic_msr(num))
		error = lapic_wrmsr(vcpu->vcpu, num, val, retu);
	else if (num == MSR_EFER)
		error = svm_write_efer(sc, vcpu, val, retu);
	else
		error = svm_wrmsr(vcpu, num, val, retu);

	return (error);
}

static int
emulate_rdmsr(struct svm_vcpu *vcpu, u_int num, bool *retu)
{
	struct vmcb_state *state;
	struct svm_regctx *ctx;
	uint64_t result;
	int error;

	if (lapic_msr(num))
		error = lapic_rdmsr(vcpu->vcpu, num, &result, retu);
	else
		error = svm_rdmsr(vcpu, num, &result, retu);

	if (error == 0) {
		state = svm_get_vmcb_state(vcpu);
		ctx = svm_get_guest_regctx(vcpu);
		state->rax = result & 0xffffffff;
		ctx->sctx_rdx = result >> 32;
	}

	return (error);
}

#ifdef KTR
static const char *
exit_reason_to_str(uint64_t reason)
{
	int i;
	static char reasonbuf[32];
	static const struct {
		int reason;
		const char *str;
	} reasons[] = {
		{ .reason = VMCB_EXIT_INVALID,	.str = "invalvmcb" },
		{ .reason = VMCB_EXIT_SHUTDOWN,	.str = "shutdown" },
		{ .reason = VMCB_EXIT_NPF, 	.str = "nptfault" },
		{ .reason = VMCB_EXIT_PAUSE,	.str = "pause" },
		{ .reason = VMCB_EXIT_HLT,	.str = "hlt" },
		{ .reason = VMCB_EXIT_CPUID,	.str = "cpuid" },
		{ .reason = VMCB_EXIT_IO,	.str = "inout" },
		{ .reason = VMCB_EXIT_MC,	.str = "mchk" },
		{ .reason = VMCB_EXIT_INTR,	.str = "extintr" },
		{ .reason = VMCB_EXIT_NMI,	.str = "nmi" },
		{ .reason = VMCB_EXIT_VINTR,	.str = "vintr" },
		{ .reason = VMCB_EXIT_MSR,	.str = "msr" },
		{ .reason = VMCB_EXIT_IRET,	.str = "iret" },
		{ .reason = VMCB_EXIT_MONITOR,	.str = "monitor" },
		{ .reason = VMCB_EXIT_MWAIT,	.str = "mwait" },
		{ .reason = VMCB_EXIT_VMRUN,	.str = "vmrun" },
		{ .reason = VMCB_EXIT_VMMCALL,	.str = "vmmcall" },
		{ .reason = VMCB_EXIT_VMLOAD,	.str = "vmload" },
		{ .reason = VMCB_EXIT_VMSAVE,	.str = "vmsave" },
		{ .reason = VMCB_EXIT_STGI,	.str = "stgi" },
		{ .reason = VMCB_EXIT_CLGI,	.str = "clgi" },
		{ .reason = VMCB_EXIT_SKINIT,	.str = "skinit" },
		{ .reason = VMCB_EXIT_ICEBP,	.str = "icebp" },
		{ .reason = VMCB_EXIT_INVD,	.str = "invd" },
		{ .reason = VMCB_EXIT_INVLPGA,	.str = "invlpga" },
		{ .reason = VMCB_EXIT_POPF,	.str = "popf" },
		{ .reason = VMCB_EXIT_PUSHF,	.str = "pushf" },
	};

	for (i = 0; i < nitems(reasons); i++) {
		if (reasons[i].reason == reason)
			return (reasons[i].str);
	}
	snprintf(reasonbuf, sizeof(reasonbuf), "%#lx", reason);
	return (reasonbuf);
}
#endif	/* KTR */

/*
 * From section "State Saved on Exit" in APMv2: nRIP is saved for all #VMEXITs
 * that are due to instruction intercepts as well as MSR and IOIO intercepts
 * and exceptions caused by INT3, INTO and BOUND instructions.
 *
 * Return 1 if the nRIP is valid and 0 otherwise.
 */
static int
nrip_valid(uint64_t exitcode)
{
	switch (exitcode) {
	case 0x00 ... 0x0F:	/* read of CR0 through CR15 */
	case 0x10 ... 0x1F:	/* write of CR0 through CR15 */
	case 0x20 ... 0x2F:	/* read of DR0 through DR15 */
	case 0x30 ... 0x3F:	/* write of DR0 through DR15 */
	case 0x43:		/* INT3 */
	case 0x44:		/* INTO */
	case 0x45:		/* BOUND */
	case 0x65 ... 0x7C:	/* VMEXIT_CR0_SEL_WRITE ... VMEXIT_MSR */
	case 0x80 ... 0x8D:	/* VMEXIT_VMRUN ... VMEXIT_XSETBV */
		return (1);
	default:
		return (0);
	}
}

static int
svm_vmexit(struct svm_softc *svm_sc, struct svm_vcpu *vcpu,
    struct vm_exit *vmexit)
{
	struct vmcb *vmcb;
	struct vmcb_state *state;
	struct vmcb_ctrl *ctrl;
	struct svm_regctx *ctx;
	enum vm_exception_class exception_class;
	uint64_t code, dr6, dr7, info1, info2, val;
	uint32_t eax, ecx, edx;
	int error __diagused, errcode_valid, handled, idtvec, reflect;
	bool retu;

	ctx = svm_get_guest_regctx(vcpu);
	vmcb = svm_get_vmcb(vcpu);
	state = &vmcb->state;
	ctrl = &vmcb->ctrl;

	handled = 0;
	code = ctrl->exitcode;
	info1 = ctrl->exitinfo1;
	info2 = ctrl->exitinfo2;
	vmm_stat_incr(vcpu->vcpu, VMEXIT_COUNT, 1);
	if (code == VMCB_EXIT_SHUTDOWN) {
		/* The saved RIP is undefined after an intercepted shutdown. */
		vmexit->exitcode = VM_EXITCODE_BOGUS;
		vmexit->rip = vcpu->nextrip;
		vmexit->inst_length = 0;
		(void)vm_suspend(svm_sc->vm, VM_SUSPEND_TRIPLEFAULT);
		return (1);
	}

	vmexit->exitcode = VM_EXITCODE_BOGUS;
	vmexit->rip = state->rip;
	vmexit->inst_length = nrip_valid(code) ? ctrl->nrip - state->rip : 0;

	/*
	 * #VMEXIT(INVALID) needs to be handled early because the VMCB is
	 * in an inconsistent state and can trigger assertions that would
	 * never happen otherwise.
	 */
	if (code == VMCB_EXIT_INVALID) {
		vm_exit_svm(vmexit, code, info1, info2);
		return (0);
	}

	KASSERT((ctrl->eventinj & VMCB_EVENTINJ_VALID) == 0, ("%s: event "
	    "injection valid bit is set %#lx", __func__, ctrl->eventinj));

	KASSERT(vmexit->inst_length >= 0 && vmexit->inst_length <= 15,
	    ("invalid inst_length %d: code (%#lx), info1 (%#lx), info2 (%#lx)",
	    vmexit->inst_length, code, info1, info2));

	svm_update_virqinfo(vcpu);
	svm_save_intinfo(svm_sc, vcpu);

	switch (code) {
	case VMCB_EXIT_IRET:
		/*
		 * Restart execution at "iret" but with the intercept cleared.
		 */
		vmexit->inst_length = 0;
		clear_nmi_blocking(vcpu);
		handled = 1;
		break;
	case VMCB_EXIT_VINTR:	/* interrupt window exiting */
		vmm_stat_incr(vcpu->vcpu, VMEXIT_VINTR, 1);
		handled = 1;
		break;
	case VMCB_EXIT_INTR:	/* external interrupt */
		vmm_stat_incr(vcpu->vcpu, VMEXIT_EXTINT, 1);
		handled = 1;
		break;
	case VMCB_EXIT_NMI:	/* external NMI */
		handled = 1;
		break;
	case 0x40 ... 0x5F:
		vmm_stat_incr(vcpu->vcpu, VMEXIT_EXCEPTION, 1);
		reflect = 1;
		errcode_valid = 0;
		exception_class = VM_EXCEPTION_FAULT;
		idtvec = code - 0x40;
		switch (idtvec) {
		case IDT_MC:
			/*
			 * Call the machine check handler by hand. Also don't
			 * reflect the machine check back into the guest.
			 */
			reflect = 0;
			SVM_CTR0(vcpu, "Vectoring to MCE handler");
			__asm __volatile("int $18");
			break;
		case IDT_PF:
			error = svm_setreg(vcpu, VM_REG_GUEST_CR2, info2);
			KASSERT(error == 0, ("%s: error %d updating cr2",
			    __func__, error));
			/* fallthru */
		case IDT_NP:
		case IDT_SS:
		case IDT_GP:
		case IDT_AC:
		case IDT_TS:
			errcode_valid = 1;
			break;

		case IDT_DF:
			errcode_valid = 1;
			info1 = 0;
			break;
		case IDT_DB: {
			/*
			 * Check if we are being stepped (RFLAGS.TF)
			 * and bounce vmexit to userland.
			 */
			bool stepped = 0;
			dr6 = 0;
			svm_getreg(vcpu, VM_REG_GUEST_DR6, &dr6);
			dr7 = 0;
			svm_getreg(vcpu, VM_REG_GUEST_DR7, &dr7);
			exception_class = vm_debug_exception_class(dr6, dr7);
			stepped = !!(dr6 & DBREG_DR6_BS);
			if (stepped && (vcpu->caps & (1 << VM_CAP_RFLAGS_TF))) {
				vmexit->exitcode = VM_EXITCODE_DB;
				vmexit->u.dbg.trace_trap = 1;
				vmexit->u.dbg.pushf_intercept = 0;

				if (vcpu->dbg.popf_sstep) {
					/*
					 * DB# exit was caused by stepping over
					 * popf.
					 */
					uint64_t rflags;

					vcpu->dbg.popf_sstep = 0;

					/*
					 * Update shadowed TF bit so the next
					 * setcap(..., RFLAGS_SSTEP, 0) restores
					 * the correct value
					 */
					svm_getreg(vcpu, VM_REG_GUEST_RFLAGS,
					    &rflags);
					vcpu->dbg.rflags_tf = rflags & PSL_T;
				} else if (vcpu->dbg.pushf_sstep) {
					/*
					 * DB# exit was caused by stepping over
					 * pushf.
					 */
					vcpu->dbg.pushf_sstep = 0;

					/*
					 * Adjusting the pushed rflags after a
					 * restarted pushf instruction must be
					 * handled outside of svm.c due to the
					 * critical_enter() lock being held.
					 */
					vmexit->u.dbg.pushf_intercept = 1;
					vmexit->u.dbg.tf_shadow_val =
					    vcpu->dbg.rflags_tf;
					svm_paging_info(svm_get_vmcb(vcpu),
					    &vmexit->u.dbg.paging);
				}

				/* Clear DR6 "single-step" bit. */
				dr6 &= ~DBREG_DR6_BS;
				error = svm_setreg(vcpu, VM_REG_GUEST_DR6, dr6);
				KASSERT(error == 0,
				    ("%s: error %d updating DR6\r\n", __func__,
					error));

				reflect = 0;
			}
			break;
		}
		case IDT_BP:
			exception_class = VM_EXCEPTION_TRAP;
			vmexit->exitcode = VM_EXITCODE_BPT;
			vmexit->u.bpt.inst_length = vmexit->inst_length;
			vmexit->inst_length = 0;

			reflect = 0;
			break;
		case IDT_OF:
			exception_class = VM_EXCEPTION_TRAP;
			goto software_exception;
		case IDT_BR:
			exception_class = VM_EXCEPTION_FAULT;
software_exception:
			/*
			 * The 'nrip' field is populated for INT3, INTO and
			 * BOUND exceptions and this also implies that
			 * 'inst_length' is non-zero.
			 *
			 * Reset 'inst_length' to zero so the guest %rip at
			 * event injection is identical to what it was when
			 * the exception originally happened.
			 */
			SVM_CTR2(vcpu, "Reset inst_length from %d "
			    "to zero before injecting exception %d",
			    vmexit->inst_length, idtvec);
			vmexit->inst_length = 0;
			/* fallthru */
		default:
			errcode_valid = 0;
			info1 = 0;
			break;
		}

		if (reflect) {
			KASSERT(vmexit->inst_length == 0,
			    ("invalid inst_length (%d) "
			     "when reflecting exception %d into guest",
				vmexit->inst_length, idtvec));
			/* Reflect the exception back into the guest */
			SVM_CTR2(vcpu, "Reflecting exception "
			    "%d/%#x into the guest", idtvec, (int)info1);
			error = vm_inject_exception_class(vcpu->vcpu, idtvec,
			    errcode_valid, info1, 0, exception_class);
			KASSERT(error == 0, ("%s: vm_inject_exception error %d",
			    __func__, error));
			handled = 1;
		}
		break;
	case VMCB_EXIT_MSR:	/* MSR access. */
		eax = state->rax;
		ecx = ctx->sctx_rcx;
		edx = ctx->sctx_rdx;
		retu = false;

		if (info1) {
			vmm_stat_incr(vcpu->vcpu, VMEXIT_WRMSR, 1);
			val = (uint64_t)edx << 32 | eax;
			SVM_CTR2(vcpu, "wrmsr %#x val %#lx", ecx, val);
			if (emulate_wrmsr(svm_sc, vcpu, ecx, val, &retu)) {
				vmexit->exitcode = VM_EXITCODE_WRMSR;
				vmexit->u.msr.code = ecx;
				vmexit->u.msr.wval = val;
			} else if (!retu) {
				handled = 1;
			} else {
				KASSERT(vmexit->exitcode != VM_EXITCODE_BOGUS,
				    ("emulate_wrmsr retu with bogus exitcode"));
			}
		} else {
			SVM_CTR1(vcpu, "rdmsr %#x", ecx);
			vmm_stat_incr(vcpu->vcpu, VMEXIT_RDMSR, 1);
			if (emulate_rdmsr(vcpu, ecx, &retu)) {
				vmexit->exitcode = VM_EXITCODE_RDMSR;
				vmexit->u.msr.code = ecx;
			} else if (!retu) {
				handled = 1;
			} else {
				KASSERT(vmexit->exitcode != VM_EXITCODE_BOGUS,
				    ("emulate_rdmsr retu with bogus exitcode"));
			}
		}
		break;
	case VMCB_EXIT_IO:
		handled = svm_handle_io(vcpu, vmcb, vmexit);
		vmm_stat_incr(vcpu->vcpu, VMEXIT_INOUT, 1);
		break;
	case VMCB_EXIT_CPUID:
	{
		uint64_t rax, rbx, rcx, rdx;

		vmm_stat_incr(vcpu->vcpu, VMEXIT_CPUID, 1);
		rax = state->rax;
		rbx = ctx->sctx_rbx;
		rcx = ctx->sctx_rcx;
		rdx = ctx->sctx_rdx;
		handled = x86_emulate_cpuid(vcpu->vcpu, &rax, &rbx, &rcx,
		    &rdx);
		state->rax = rax;
		ctx->sctx_rbx = rbx;
		ctx->sctx_rcx = rcx;
		ctx->sctx_rdx = rdx;
		break;
	}
	case VMCB_EXIT_HLT:
		vmm_stat_incr(vcpu->vcpu, VMEXIT_HLT, 1);
		vmexit->exitcode = VM_EXITCODE_HLT;
		vmexit->u.hlt.rflags = state->rflags;
		break;
	case VMCB_EXIT_PAUSE:
		vmexit->exitcode = VM_EXITCODE_PAUSE;
		vmm_stat_incr(vcpu->vcpu, VMEXIT_PAUSE, 1);
		break;
	case VMCB_EXIT_NPF:
		/* EXITINFO2 contains the faulting guest physical address */
		if (info1 & VMCB_NPF_INFO1_RSV) {
			SVM_CTR2(vcpu, "nested page fault with "
			    "reserved bits set: info1(%#lx) info2(%#lx)",
			    info1, info2);
		} else if (vm_mem_allocated(vcpu->vcpu, info2) ||
		    ppt_is_mmio(svm_sc->vm, info2)) {
			vmexit->exitcode = VM_EXITCODE_PAGING;
			vmexit->u.paging.gpa = info2;
			vmexit->u.paging.fault_type = npf_fault_type(info1);
			vmm_stat_incr(vcpu->vcpu, VMEXIT_NESTED_FAULT, 1);
			SDT_PROBE5(vmm, svm, exit, nestedfault, svm_sc,
			    vcpu->vcpuid, vmexit, info2, info1);
			SVM_CTR3(vcpu, "nested page fault "
			    "on gpa %#lx/%#lx at rip %#lx",
			    info2, info1, state->rip);
		} else if (svm_npf_emul_fault(info1)) {
			svm_handle_inst_emul(vmcb, info2, vmexit);
			vmm_stat_incr(vcpu->vcpu, VMEXIT_INST_EMUL, 1);
			SVM_CTR3(vcpu, "inst_emul fault "
			    "for gpa %#lx/%#lx at rip %#lx",
			    info2, info1, state->rip);
		}
		break;
	case VMCB_EXIT_MONITOR:
		vmexit->exitcode = VM_EXITCODE_MONITOR;
		break;
	case VMCB_EXIT_MWAIT:
		vmexit->exitcode = VM_EXITCODE_MWAIT;
		break;
	case VMCB_EXIT_PUSHF: {
		if (vcpu->caps & (1 << VM_CAP_RFLAGS_TF)) {
			uint64_t rflags;

			svm_getreg(vcpu, VM_REG_GUEST_RFLAGS, &rflags);
			/* Restart this instruction. */
			vmexit->inst_length = 0;
			/* Disable PUSHF intercepts - avoid a loop. */
			svm_set_intercept(vcpu, VMCB_CTRL1_INTCPT,
			    VMCB_INTCPT_PUSHF, 0);
			/* Trace restarted instruction. */
			svm_setreg(vcpu, VM_REG_GUEST_RFLAGS, (rflags | PSL_T));
			/* Let the IDT_DB handler know that pushf was stepped.
			 */
			vcpu->dbg.pushf_sstep = 1;
			handled = 1;
		}
		break;
	}
	case VMCB_EXIT_POPF: {
		if (vcpu->caps & (1 << VM_CAP_RFLAGS_TF)) {
			uint64_t rflags;

			svm_getreg(vcpu, VM_REG_GUEST_RFLAGS, &rflags);
			/* Restart this instruction */
			vmexit->inst_length = 0;
			/* Disable POPF intercepts - avoid a loop*/
			svm_set_intercept(vcpu, VMCB_CTRL1_INTCPT,
			    VMCB_INTCPT_POPF, 0);
			/* Trace restarted instruction */
			svm_setreg(vcpu, VM_REG_GUEST_RFLAGS, (rflags | PSL_T));
			vcpu->dbg.popf_sstep = 1;
			handled = 1;
		}
		break;
	}
	case VMCB_EXIT_VMRUN:
	case VMCB_EXIT_VMLOAD:
	case VMCB_EXIT_VMSAVE:
		if (!vcpu->nested_msr.exposed || !vcpu->nested_msr.svme ||
		    (state->cr0 & CR0_PE) == 0) {
			vm_inject_ud(vcpu->vcpu);
			vmexit->inst_length = 0;
			handled = 1;
			break;
		}
		if (svm_cpl(state) != 0) {
			vm_inject_gp(vcpu->vcpu);
			vmexit->inst_length = 0;
			handled = 1;
			break;
		}
		if (vcpu->nested_pending.kind !=
		    SVM_NESTED_INSTRUCTION_NONE) {
			vcpu->nested_pending.kind =
			    SVM_NESTED_INSTRUCTION_NONE;
			vm_exit_svm(vmexit, code, info1, info2);
			break;
		}
		if (vmexit->inst_length == 0) {
			vm_exit_svm(vmexit, code, info1, info2);
			break;
		}
		vcpu->nested_pending.kind = code == VMCB_EXIT_VMRUN ?
		    SVM_NESTED_INSTRUCTION_VMRUN :
		    code == VMCB_EXIT_VMLOAD ?
		    SVM_NESTED_INSTRUCTION_VMLOAD :
		    SVM_NESTED_INSTRUCTION_VMSAVE;
		vcpu->nested_pending.vmcb_gpa = state->rax;
		vcpu->nested_pending.rip = state->rip;
		vcpu->nested_pending.next_rip = ctrl->nrip;
		vmexit->exitcode = VM_EXITCODE_VMM_INTERNAL;
		vmexit->inst_length = 0;
		break;
	case VMCB_EXIT_VMMCALL:
	case VMCB_EXIT_SKINIT:
	case VMCB_EXIT_ICEBP:
		vm_inject_ud(vcpu->vcpu);
		vmexit->inst_length = 0;
		handled = 1;
		break;
	case VMCB_EXIT_INVLPGA:
		if (!vcpu->nested_msr.exposed || !vcpu->nested_msr.svme ||
		    (state->cr0 & CR0_PE) == 0) {
			vm_inject_ud(vcpu->vcpu);
			vmexit->inst_length = 0;
		} else if (svm_cpl(state) != 0) {
			vm_inject_gp(vcpu->vcpu);
			vmexit->inst_length = 0;
		} else if (vmexit->inst_length == 0) {
			vm_exit_svm(vmexit, code, info1, info2);
			break;
		} else {
			/* Flush conservatively across L1 and all L2 ASIDs. */
			vcpu->asid.gen = 0;
			vcpu->nested_asid.gen = 0;
		}
		handled = 1;
		break;
	case VMCB_EXIT_STGI:
	case VMCB_EXIT_CLGI:
		if (!vcpu->nested_msr.exposed || !vcpu->nested_msr.svme ||
		    (state->cr0 & CR0_PE) == 0) {
			vm_inject_ud(vcpu->vcpu);
			vmexit->inst_length = 0;
		} else if (svm_cpl(state) != 0) {
			vm_inject_gp(vcpu->vcpu);
			vmexit->inst_length = 0;
		} else if (vmexit->inst_length == 0) {
			vm_exit_svm(vmexit, code, info1, info2);
			break;
		} else
			vcpu->nested_gif = code == VMCB_EXIT_STGI;
		handled = 1;
		break;
	case VMCB_EXIT_INVD:
	case VMCB_EXIT_WBINVD:
		/* ignore exit */
		handled = 1;
		break;
	default:
		vmm_stat_incr(vcpu->vcpu, VMEXIT_UNKNOWN, 1);
		break;
	}

	SVM_CTR4(vcpu, "%s %s vmexit at %#lx/%d",
	    handled ? "handled" : "unhandled", exit_reason_to_str(code),
	    vmexit->rip, vmexit->inst_length);

	if (handled) {
		vmexit->rip += vmexit->inst_length;
		vmexit->inst_length = 0;
		state->rip = vmexit->rip;
	} else {
		if (vmexit->exitcode == VM_EXITCODE_BOGUS) {
			/*
			 * If this VM exit was not claimed by anybody then
			 * treat it as a generic SVM exit.
			 */
			vm_exit_svm(vmexit, code, info1, info2);
		} else {
			/*
			 * The exitcode and collateral have been populated.
			 * The VM exit will be processed further in userland.
			 */
		}
	}
	return (handled);
}

static void
svm_inj_intinfo(struct svm_softc *svm_sc, struct svm_vcpu *vcpu)
{
	struct vm_intinfo_snapshot pending;
	uint64_t intinfo;
	int error, retry;

	if (vcpu->nested_msr.exposed && !vcpu->nested_gif) {
		for (retry = 0; retry < 4; retry++) {
			error = vm_entry_intinfo_peek(vcpu->vcpu, &pending);
			if (error != 0)
				return;
			if (pending.valid &&
			    ((pending.entry & VM_INTINFO_TYPE) ==
			    VM_INTINFO_HWINTR ||
			    (pending.entry & VM_INTINFO_TYPE) == VM_INTINFO_NMI))
				return;
			error = vm_entry_intinfo_commit(vcpu->vcpu, &pending);
			if (error != EAGAIN)
				break;
		}
		if (error != 0 || !pending.valid)
			return;
		intinfo = pending.entry;
	} else if (!vm_entry_intinfo(vcpu->vcpu, &intinfo))
		return;

	KASSERT(VMCB_EXITINTINFO_VALID(intinfo), ("%s: entry intinfo is not "
	    "valid: %#lx", __func__, intinfo));

	svm_eventinject(vcpu, VMCB_EXITINTINFO_TYPE(intinfo),
		VMCB_EXITINTINFO_VECTOR(intinfo),
		VMCB_EXITINTINFO_EC(intinfo),
		VMCB_EXITINTINFO_EC_VALID(intinfo));
	vmm_stat_incr(vcpu->vcpu, VCPU_INTINFO_INJECTED, 1);
	SVM_CTR1(vcpu, "Injected entry intinfo: %#lx", intinfo);
}

/*
 * Inject event to virtual cpu.
 */
static void
svm_inj_interrupts(struct svm_softc *sc, struct svm_vcpu *vcpu,
    struct vlapic *vlapic)
{
	struct vmcb_ctrl *ctrl;
	struct vmcb_state *state;
	uint8_t v_tpr;
	int vector, need_intr_window;
	int extint_pending;

	if (vcpu->caps & (1 << VM_CAP_MASK_HWINTR)) {
		return;
	}

	state = svm_get_vmcb_state(vcpu);
	ctrl  = svm_get_vmcb_ctrl(vcpu);

	need_intr_window = 0;

	if (vcpu->nextrip != state->rip) {
		ctrl->intr_shadow = 0;
		SVM_CTR2(vcpu, "Guest interrupt blocking "
		    "cleared due to rip change: %#lx/%#lx",
		    vcpu->nextrip, state->rip);
	}

	/*
	 * Inject pending events or exceptions for this vcpu.
	 *
	 * An event might be pending because the previous #VMEXIT happened
	 * during event delivery (i.e. ctrl->exitintinfo).
	 *
	 * An event might also be pending because an exception was injected
	 * by the hypervisor (e.g. #PF during instruction emulation).
	 */
	svm_inj_intinfo(sc, vcpu);
	if (vcpu->nested_msr.exposed && !vcpu->nested_gif)
		goto done;

	/* NMI event has priority over interrupts. */
	if (vm_nmi_pending(vcpu->vcpu)) {
		if (nmi_blocked(vcpu)) {
			/*
			 * Can't inject another NMI if the guest has not
			 * yet executed an "iret" after the last NMI.
			 */
			SVM_CTR0(vcpu, "Cannot inject NMI due "
			    "to NMI-blocking");
		} else if (ctrl->intr_shadow) {
			/*
			 * Can't inject an NMI if the vcpu is in an intr_shadow.
			 */
			SVM_CTR0(vcpu, "Cannot inject NMI due to "
			    "interrupt shadow");
			need_intr_window = 1;
			goto done;
		} else if (ctrl->eventinj & VMCB_EVENTINJ_VALID) {
			/*
			 * If there is already an exception/interrupt pending
			 * then defer the NMI until after that.
			 */
			SVM_CTR1(vcpu, "Cannot inject NMI due to "
			    "eventinj %#lx", ctrl->eventinj);

			/*
			 * Use self-IPI to trigger a VM-exit as soon as
			 * possible after the event injection is completed.
			 *
			 * This works only if the external interrupt exiting
			 * is at a lower priority than the event injection.
			 *
			 * Although not explicitly specified in APMv2 the
			 * relative priorities were verified empirically.
			 */
			ipi_cpu(curcpu, IPI_AST);	/* XXX vmm_ipinum? */
		} else {
			vm_nmi_clear(vcpu->vcpu);

			/* Inject NMI, vector number is not used */
			svm_eventinject(vcpu, VMCB_EVENTINJ_TYPE_NMI,
			    IDT_NMI, 0, false);

			/* virtual NMI blocking is now in effect */
			enable_nmi_blocking(vcpu);

			SVM_CTR0(vcpu, "Injecting vNMI");
		}
	}

	extint_pending = vm_extint_pending(vcpu->vcpu);
	if (!extint_pending) {
		if (!vlapic_pending_intr(vlapic, &vector))
			goto done;
		KASSERT(vector >= 16 && vector <= 255,
		    ("invalid vector %d from local APIC", vector));
	} else {
		/* Ask the legacy pic for a vector to inject */
		vatpic_pending_intr(sc->vm, &vector);
		KASSERT(vector >= 0 && vector <= 255,
		    ("invalid vector %d from INTR", vector));
	}

	/*
	 * If the guest has disabled interrupts or is in an interrupt shadow
	 * then we cannot inject the pending interrupt.
	 */
	if ((state->rflags & PSL_I) == 0) {
		SVM_CTR2(vcpu, "Cannot inject vector %d due to "
		    "rflags %#lx", vector, state->rflags);
		need_intr_window = 1;
		goto done;
	}

	if (ctrl->intr_shadow) {
		SVM_CTR1(vcpu, "Cannot inject vector %d due to "
		    "interrupt shadow", vector);
		need_intr_window = 1;
		goto done;
	}

	if (ctrl->eventinj & VMCB_EVENTINJ_VALID) {
		SVM_CTR2(vcpu, "Cannot inject vector %d due to "
		    "eventinj %#lx", vector, ctrl->eventinj);
		need_intr_window = 1;
		goto done;
	}

	svm_eventinject(vcpu, VMCB_EVENTINJ_TYPE_INTR, vector, 0, false);

	if (!extint_pending) {
		vlapic_intr_accepted(vlapic, vector);
	} else {
		vm_extint_clear(vcpu->vcpu);
		vatpic_intr_accepted(sc->vm, vector);
	}

	/*
	 * Force a VM-exit as soon as the vcpu is ready to accept another
	 * interrupt. This is done because the PIC might have another vector
	 * that it wants to inject. Also, if the APIC has a pending interrupt
	 * that was preempted by the ExtInt then it allows us to inject the
	 * APIC vector as soon as possible.
	 */
	need_intr_window = 1;
done:
	/*
	 * The guest can modify the TPR by writing to %CR8. In guest mode
	 * the processor reflects this write to V_TPR without hypervisor
	 * intervention.
	 *
	 * The guest can also modify the TPR by writing to it via the memory
	 * mapped APIC page. In this case, the write will be emulated by the
	 * hypervisor. For this reason V_TPR must be updated before every
	 * VMRUN.
	 */
	v_tpr = vlapic_get_cr8(vlapic);
	KASSERT(v_tpr <= 15, ("invalid v_tpr %#x", v_tpr));
	if (ctrl->v_tpr != v_tpr) {
		SVM_CTR2(vcpu, "VMCB V_TPR changed from %#x to %#x",
		    ctrl->v_tpr, v_tpr);
		ctrl->v_tpr = v_tpr;
		svm_set_dirty(vcpu, VMCB_CACHE_TPR);
	}

	if (need_intr_window) {
		/*
		 * We use V_IRQ in conjunction with the VINTR intercept to
		 * trap into the hypervisor as soon as a virtual interrupt
		 * can be delivered.
		 *
		 * Since injected events are not subject to intercept checks
		 * we need to ensure that the V_IRQ is not actually going to
		 * be delivered on VM entry. The KASSERT below enforces this.
		 */
		KASSERT((ctrl->eventinj & VMCB_EVENTINJ_VALID) != 0 ||
		    (state->rflags & PSL_I) == 0 || ctrl->intr_shadow,
		    ("Bogus intr_window_exiting: eventinj (%#lx), "
		    "intr_shadow (%u), rflags (%#lx)",
		    ctrl->eventinj, ctrl->intr_shadow, state->rflags));
		enable_intr_window_exiting(vcpu);
	} else {
		disable_intr_window_exiting(vcpu);
	}
}

static __inline void
restore_host_tss(void)
{
	struct system_segment_descriptor *tss_sd;

	/*
	 * The TSS descriptor was in use prior to launching the guest so it
	 * has been marked busy.
	 *
	 * 'ltr' requires the descriptor to be marked available so change the
	 * type to "64-bit available TSS".
	 */
	tss_sd = PCPU_GET(tss);
	tss_sd->sd_type = SDT_SYSTSS;
	ltr(GSEL(GPROC0_SEL, SEL_KPL));
}

static void
svm_pmap_activate_context(struct svm_vcpu *vcpu, pmap_t pmap,
    struct vmcb_ctrl *ctrl, struct asid *owner_asid, long *owner_eptgen,
    bool mark_vmcb_dirty)
{
	long eptgen;
	int cpu;
	bool alloc_asid;

	cpu = curcpu;
	CPU_SET_ATOMIC(cpu, &pmap->pm_active);
	smr_enter(pmap->pm_eptsmr);

	/*
	 * The TLB entries associated with the vcpu's ASID are not valid
	 * if either of the following conditions is true:
	 *
	 * 1. The vcpu's ASID generation is different than the host cpu's
	 *    ASID generation. This happens when the vcpu migrates to a new
	 *    host cpu. It can also happen when the number of vcpus executing
	 *    on a host cpu is greater than the number of ASIDs available.
	 *
	 * 2. The pmap generation number is different than the value cached in
	 *    the 'vcpustate'. This happens when the host invalidates pages
	 *    belonging to the guest.
	 *
	 *	asidgen		eptgen	      Action
	 *	mismatch	mismatch
	 *	   0		   0		(a)
	 *	   0		   1		(b1) or (b2)
	 *	   1		   0		(c)
	 *	   1		   1		(d)
	 *
	 * (a) There is no mismatch in eptgen or ASID generation and therefore
	 *     no further action is needed.
	 *
	 * (b1) If the cpu supports FlushByAsid then the vcpu's ASID is
	 *      retained and the TLB entries associated with this ASID
	 *      are flushed by VMRUN.
	 *
	 * (b2) If the cpu does not support FlushByAsid then a new ASID is
	 *      allocated.
	 *
	 * (c) A new ASID is allocated.
	 *
	 * (d) A new ASID is allocated.
	 */

	alloc_asid = false;
	eptgen = atomic_load_long(&pmap->pm_eptgen);
	ctrl->tlb_ctrl = VMCB_TLB_FLUSH_NOTHING;

	if (owner_asid->gen != asid[cpu].gen) {
		alloc_asid = true;	/* (c) and (d) */
	} else if (*owner_eptgen != eptgen) {
		if (flush_by_asid())
			ctrl->tlb_ctrl = VMCB_TLB_FLUSH_GUEST;	/* (b1) */
		else
			alloc_asid = true;			/* (b2) */
	} else {
		/*
		 * This is the common case (a).
		 */
		KASSERT(!alloc_asid, ("ASID allocation not necessary"));
		KASSERT(ctrl->tlb_ctrl == VMCB_TLB_FLUSH_NOTHING,
		    ("Invalid VMCB tlb_ctrl: %#x", ctrl->tlb_ctrl));
	}

	if (alloc_asid) {
		if (++asid[cpu].num >= nasid) {
			asid[cpu].num = 1;
			if (++asid[cpu].gen == 0)
				asid[cpu].gen = 1;
			/*
			 * If this cpu does not support "flush-by-asid"
			 * then flush the entire TLB on a generation
			 * bump. Subsequent ASID allocation in this
			 * generation can be done without a TLB flush.
			 */
			if (!flush_by_asid())
				ctrl->tlb_ctrl = VMCB_TLB_FLUSH_ALL;
		}
		owner_asid->gen = asid[cpu].gen;
		owner_asid->num = asid[cpu].num;

		ctrl->asid = owner_asid->num;
		if (mark_vmcb_dirty)
			svm_set_dirty(vcpu, VMCB_CACHE_ASID);
		else
			ctrl->vmcb_clean = 0;
		/*
		 * If this cpu supports "flush-by-asid" then the TLB
		 * was not flushed after the generation bump. The TLB
		 * is flushed selectively after every new ASID allocation.
		 */
		if (flush_by_asid())
			ctrl->tlb_ctrl = VMCB_TLB_FLUSH_GUEST;
	}
	*owner_eptgen = eptgen;

	KASSERT(ctrl->asid != 0, ("Guest ASID must be non-zero"));
	KASSERT(ctrl->asid == owner_asid->num,
	    ("ASID mismatch: %u/%u", ctrl->asid, owner_asid->num));
}

static void
svm_pmap_activate(struct svm_vcpu *vcpu, pmap_t pmap)
{

	svm_pmap_activate_context(vcpu, pmap, svm_get_vmcb_ctrl(vcpu),
	    &vcpu->asid, &vcpu->eptgen, true);
}

static void
svm_pmap_deactivate(pmap_t pmap)
{
	smr_exit(pmap->pm_eptsmr);
	CPU_CLR_ATOMIC(curcpu, &pmap->pm_active);
}

static __inline void
disable_gintr(void)
{

	__asm __volatile("clgi");
}

static __inline void
enable_gintr(void)
{

        __asm __volatile("stgi");
}

static __inline void
svm_dr_enter_guest(struct svm_regctx *gctx)
{

	/* Save host control debug registers. */
	gctx->host_dr7 = rdr7();
	gctx->host_debugctl = rdmsr(MSR_DEBUGCTLMSR);

	/*
	 * Disable debugging in DR7 and DEBUGCTL to avoid triggering
	 * exceptions in the host based on the guest DRx values.  The
	 * guest DR6, DR7, and DEBUGCTL are saved/restored in the
	 * VMCB.
	 */
	load_dr7(0);
	wrmsr(MSR_DEBUGCTLMSR, 0);

	/* Save host debug registers. */
	gctx->host_dr0 = rdr0();
	gctx->host_dr1 = rdr1();
	gctx->host_dr2 = rdr2();
	gctx->host_dr3 = rdr3();
	gctx->host_dr6 = rdr6();

	/* Restore guest debug registers. */
	load_dr0(gctx->sctx_dr0);
	load_dr1(gctx->sctx_dr1);
	load_dr2(gctx->sctx_dr2);
	load_dr3(gctx->sctx_dr3);
}

static __inline void
svm_dr_leave_guest(struct svm_regctx *gctx)
{

	/* Save guest debug registers. */
	gctx->sctx_dr0 = rdr0();
	gctx->sctx_dr1 = rdr1();
	gctx->sctx_dr2 = rdr2();
	gctx->sctx_dr3 = rdr3();

	/*
	 * Restore host debug registers.  Restore DR7 and DEBUGCTL
	 * last.
	 */
	load_dr0(gctx->host_dr0);
	load_dr1(gctx->host_dr1);
	load_dr2(gctx->host_dr2);
	load_dr3(gctx->host_dr3);
	load_dr6(gctx->host_dr6);
	wrmsr(MSR_DEBUGCTLMSR, gctx->host_debugctl);
	load_dr7(gctx->host_dr7);
}

static uint64_t
svm_nested_pending_event(struct svm_vcpu *vcpu, struct vlapic *vlapic)
{
	const struct vmcb_ctrl *ctrl;
	struct vm_intinfo_snapshot pending;
	struct svm_nested_pending_event event;
	bool queued_irq, queued_nmi;

	if (vm_entry_intinfo_peek(vcpu->vcpu, &pending) != 0)
		return (0);
	queued_irq = queued_nmi = false;
	if (pending.valid) {
		if ((pending.entry & VM_INTINFO_TYPE) == VM_INTINFO_NMI)
			queued_nmi = true;
		else if ((pending.entry & VM_INTINFO_TYPE) ==
		    VM_INTINFO_HWINTR)
			queued_irq = true;
		else
			/* A queued L0 software event has entry priority. */
			return (0);
	}
	ctrl = &vcpu->nested_vmcb02->ctrl;
	event = (struct svm_nested_pending_event) {
		.l1_intercepts = vcpu->nested_vmcb12->ctrl.intercept[
		    VMCB_CTRL1_INTCPT],
		.l1_rflags = vcpu->vmcb->state.rflags,
		.l2_rflags = vcpu->nested_vmcb02->state.rflags,
		.eventinj = ctrl->eventinj,
		.exitintinfo = ctrl->exitintinfo,
		.l1_intr_masking =
		    vcpu->nested_vmcb12->ctrl.v_intr_masking != 0,
		.nmi_pending = queued_nmi || vm_nmi_pending(vcpu->vcpu),
		.nmi_blocked = ctrl->v_nmi_blocking != 0,
		.irq_pending = queued_irq || vm_extint_pending(vcpu->vcpu) ||
		    vlapic_pending_intr(vlapic, NULL),
		.mask_hwintr =
		    (vcpu->caps & (1 << VM_CAP_MASK_HWINTR)) != 0,
	};
	return (svm_nested_pending_event_exit(&event));
}

/* V_IRQ is borrowed only for this one VMRUN; never expose it to VMCB12. */
struct svm_nested_irq_window {
	bool active;
	uint8_t v_irq;
	uint8_t v_ign_tpr;
	uint8_t v_intr_vector;
	uint32_t vintr_intercept;
};

static uint64_t *
svm_nested_vnmi_slot(uint64_t gpas[SVM_NESTED_VNMI_SLOTS], uint64_t gpa,
    bool create)
{
	uint64_t *empty;
	int i;

	empty = NULL;
	for (i = 0; i < SVM_NESTED_VNMI_SLOTS; i++) {
		if ((gpas[i] & ~SVM_NESTED_VNMI_BLOCKED) ==
		    (gpa | SVM_NESTED_VNMI_VALID))
			return (&gpas[i]);
		if (empty == NULL && gpas[i] == 0)
			empty = &gpas[i];
	}
	return (create ? empty : NULL);
}

static int
svm_nested_vnmi_prepare(struct vmcb *vmcb02, uint64_t gpa,
    uint64_t gpas[SVM_NESTED_VNMI_SLOTS])
{
	struct vmcb_ctrl *ctrl;
	uint64_t *slot;
	bool injected_nmi;

	if ((svm_feature & AMD_CPUID_SVM_VNMI) == 0)
		return (0);
	ctrl = &vmcb02->ctrl;
	injected_nmi = (ctrl->eventinj & VMCB_EVENTINJ_VALID) != 0 &&
	    VMCB_EXITINTINFO_TYPE(ctrl->eventinj) == VMCB_EVENTINJ_TYPE_NMI;
	slot = svm_nested_vnmi_slot(gpas, gpa, injected_nmi);
	if (injected_nmi && slot == NULL)
		return (ENOSPC);
	if (slot != NULL && *slot == 0)
		*slot = gpa | SVM_NESTED_VNMI_VALID;
	ctrl->v_nmi_enable = 1;
	ctrl->v_nmi_blocking = slot != NULL &&
	    (*slot & SVM_NESTED_VNMI_BLOCKED) != 0;
	return (0);
}

static void
svm_nested_vnmi_sync(struct svm_vcpu *vcpu)
{
	struct vmcb_ctrl *ctrl;
	uint64_t *slot;

	ctrl = &vcpu->nested_vmcb02->ctrl;
	slot = svm_nested_vnmi_slot(vcpu->nested_vnmi_gpas,
	    vcpu->nested_vmcb12_gpa, false);
	if (slot == NULL)
		return;
	if (ctrl->v_nmi_blocking)
		*slot |= SVM_NESTED_VNMI_BLOCKED;
	else if (((ctrl->eventinj | ctrl->exitintinfo) &
	    VMCB_EVENTINJ_VALID) == 0)
		*slot = 0;
	else
		*slot &= ~SVM_NESTED_VNMI_BLOCKED;
}

static void
svm_nested_inj_nmi(struct svm_vcpu *vcpu)
{
	struct vm_intinfo_snapshot pending;
	struct vmcb_ctrl *ctrl;
	uint64_t *slot;

	if ((svm_feature & AMD_CPUID_SVM_VNMI) == 0 ||
	    (vcpu->caps & (1 << VM_CAP_MASK_HWINTR)) != 0 ||
	    !vm_nmi_pending(vcpu->vcpu) ||
	    (vcpu->nested_vmcb12->ctrl.intercept[VMCB_CTRL1_INTCPT] &
	    VMCB_INTCPT_NMI) != 0)
		return;
	if (vm_entry_intinfo_peek(vcpu->vcpu, &pending) != 0 ||
	    pending.valid)
		return;
	ctrl = &vcpu->nested_vmcb02->ctrl;
	if (ctrl->v_nmi_blocking || ctrl->intr_shadow ||
	    ((ctrl->eventinj | ctrl->exitintinfo) & VMCB_EVENTINJ_VALID) != 0)
		return;
	slot = svm_nested_vnmi_slot(vcpu->nested_vnmi_gpas,
	    vcpu->nested_vmcb12_gpa, true);
	if (slot == NULL)
		return;
	*slot = vcpu->nested_vmcb12_gpa | SVM_NESTED_VNMI_VALID;
	ctrl->v_nmi_enable = 1;
	vm_nmi_clear(vcpu->vcpu);
	svm_eventinject_to_vmcb(vcpu, ctrl, VMCB_EVENTINJ_TYPE_NMI,
	    IDT_NMI, 0, false);
}

static void
svm_nested_inj_irq(struct svm_softc *sc, struct svm_vcpu *vcpu,
    struct vlapic *vlapic, struct svm_nested_irq_window *window)
{
	struct vm_intinfo_snapshot pending;
	struct vmcb_ctrl *ctrl;
	uint64_t rflags;
	int vector;
	bool extint_pending, queued_hwintr;

	queued_hwintr = false;
	ctrl = &vcpu->nested_vmcb02->ctrl;
	if ((vcpu->caps & (1 << VM_CAP_MASK_HWINTR)) != 0 ||
	    (vm_nmi_pending(vcpu->vcpu) && !ctrl->v_nmi_blocking) ||
	    (vcpu->nested_vmcb12->ctrl.intercept[VMCB_CTRL1_INTCPT] &
	    VMCB_INTCPT_INTR) != 0)
		return;
	if (vm_entry_intinfo_peek(vcpu->vcpu, &pending) != 0)
		return;
	if (pending.valid) {
		if ((pending.entry & VM_INTINFO_TYPE) != VM_INTINFO_HWINTR)
			return;
		queued_hwintr = true;
	}
	extint_pending = !queued_hwintr && vm_extint_pending(vcpu->vcpu);
	if (queued_hwintr)
		vector = VM_INTINFO_VECTOR(pending.entry);
	else if (!extint_pending) {
		if (!vlapic_pending_intr(vlapic, &vector))
			return;
		KASSERT(vector >= 16 && vector <= 255,
		    ("invalid vector %d from local APIC", vector));
	} else {
		vatpic_pending_intr(sc->vm, &vector);
		KASSERT(vector >= 0 && vector <= 255,
		    ("invalid vector %d from INTR", vector));
	}
	rflags = vcpu->nested_vmcb12->ctrl.v_intr_masking != 0 ?
	    vcpu->vmcb->state.rflags : vcpu->nested_vmcb02->state.rflags;
	if ((rflags & PSL_I) == 0 || ctrl->intr_shadow != 0 ||
	    ((ctrl->eventinj | ctrl->exitintinfo) & VMCB_EVENTINJ_VALID) != 0) {
		/*
		 * VMCB02 uses L0's interrupt masking mode.  If L1 disabled
		 * masking, L2.IF can be clear while the hardware window sees
		 * L1.IF set.  A borrowed V_IRQ would then exit immediately forever.
		 */
		if (vcpu->nested_vmcb12->ctrl.v_intr_masking == 0 &&
		    (vcpu->nested_vmcb02->state.rflags & PSL_I) == 0)
			return;
		/* Borrow V_IRQ to wake L0 when the blocked window opens. */
		window->active = true;
		window->v_irq = ctrl->v_irq;
		window->v_ign_tpr = ctrl->v_ign_tpr;
		window->v_intr_vector = ctrl->v_intr_vector;
		window->vintr_intercept = ctrl->intercept[VMCB_CTRL1_INTCPT] &
		    VMCB_INTCPT_VINTR;
		ctrl->v_irq = 1;
		ctrl->v_ign_tpr = 1;
		ctrl->v_intr_vector = 0;
		ctrl->intercept[VMCB_CTRL1_INTCPT] |= VMCB_INTCPT_VINTR;
		return;
	}
	/* The queued vector was already considered by svm_nested_inj_intinfo. */
	if (queued_hwintr)
		return;
	ctrl->eventinj = VMCB_EVENTINJ_VALID |
	    ((uint64_t)VMCB_EVENTINJ_TYPE_INTR << 8) | vector;
	if (extint_pending) {
		vm_extint_clear(vcpu->vcpu);
		vatpic_intr_accepted(sc->vm, vector);
	} else
		vlapic_intr_accepted(vlapic, vector);
}

/*
 * Consume queued L0 events when L2 can accept them.  Hardware IRQs may
 * require an L1-requested exit; virtual NMIs use VMCB02 completion state.
 */
static void
svm_nested_inj_intinfo(struct svm_vcpu *vcpu)
{
	struct vm_intinfo_snapshot pending;
	struct vmcb_ctrl *ctrl;
	uint64_t intinfo;
	int error, retry;

	ctrl = &vcpu->nested_vmcb02->ctrl;
	if (((ctrl->eventinj | ctrl->exitintinfo) &
	    VMCB_EVENTINJ_VALID) != 0)
		return;
	for (retry = 0; retry < 4; retry++) {
		error = vm_entry_intinfo_peek(vcpu->vcpu, &pending);
		if (error != 0 || !pending.valid)
			return;
		intinfo = pending.entry;
		if ((intinfo & VM_INTINFO_TYPE) == VM_INTINFO_NMI &&
		    ((svm_feature & AMD_CPUID_SVM_VNMI) == 0 ||
		    (vcpu->caps & (1 << VM_CAP_MASK_HWINTR)) != 0 ||
		    (vcpu->nested_vmcb12->ctrl.intercept[
		    VMCB_CTRL1_INTCPT] & VMCB_INTCPT_NMI) != 0 ||
		    ctrl->v_nmi_blocking || ctrl->intr_shadow != 0 ||
		    svm_nested_vnmi_slot(vcpu->nested_vnmi_gpas,
		    vcpu->nested_vmcb12_gpa, true) == NULL))
			return;
		if ((intinfo & VM_INTINFO_TYPE) == VM_INTINFO_HWINTR &&
		    ((vcpu->nested_vmcb12->ctrl.intercept[
		    VMCB_CTRL1_INTCPT] & VMCB_INTCPT_INTR) != 0 ||
		    (vcpu->caps & (1 << VM_CAP_MASK_HWINTR)) != 0 ||
		    (vm_nmi_pending(vcpu->vcpu) &&
		    !ctrl->v_nmi_blocking) || ctrl->intr_shadow != 0 ||
		    ((vcpu->nested_vmcb12->ctrl.v_intr_masking != 0 ?
		    vcpu->vmcb->state.rflags :
		    vcpu->nested_vmcb02->state.rflags) & PSL_I) == 0))
			return;
		error = vm_entry_intinfo_commit(vcpu->vcpu, &pending);
		if (error != EAGAIN)
			break;
	}
	if (error != 0)
		return;
	if ((intinfo & VM_INTINFO_TYPE) == VM_INTINFO_NMI) {
		*svm_nested_vnmi_slot(vcpu->nested_vnmi_gpas,
		    vcpu->nested_vmcb12_gpa, true) =
		    vcpu->nested_vmcb12_gpa | SVM_NESTED_VNMI_VALID;
		ctrl->v_nmi_enable = 1;
	}
	KASSERT(VMCB_EXITINTINFO_VALID(intinfo),
	    ("%s: entry intinfo is not valid: %#lx", __func__, intinfo));
	svm_eventinject_to_vmcb(vcpu, ctrl, VMCB_EXITINTINFO_TYPE(intinfo),
	    VMCB_EXITINTINFO_VECTOR(intinfo), VMCB_EXITINTINFO_EC(intinfo),
	    VMCB_EXITINTINFO_EC_VALID(intinfo));
	vmm_stat_incr(vcpu->vcpu, VCPU_INTINFO_INJECTED, 1);
}

static void
svm_nested_irq_window_restore(struct vmcb_ctrl *ctrl,
    const struct svm_nested_irq_window *window)
{
	if (!window->active)
		return;
	ctrl->v_irq = window->v_irq;
	ctrl->v_ign_tpr = window->v_ign_tpr;
	ctrl->v_intr_vector = window->v_intr_vector;
	ctrl->intercept[VMCB_CTRL1_INTCPT] &= ~VMCB_INTCPT_VINTR;
	ctrl->intercept[VMCB_CTRL1_INTCPT] |= window->vintr_intercept;
}

/*
 * Start vcpu with specified RIP.
 */
static int
svm_run(void *vcpui, register_t rip, pmap_t pmap, struct vm_eventinfo *evinfo,
    struct vmm_startup_entry_owner *entry_owner)
{
	struct svm_regctx *gctx;
	struct svm_softc *svm_sc;
	struct svm_vcpu *vcpu;
	pmap_t run_pmap;
	struct vmcb_state *state;
	struct vmcb_ctrl *ctrl;
	struct vm_exit *vmexit;
	struct vlapic *vlapic;
	struct svm_nested_irq_window irq_window;
	struct vmm_startup_entry_loop_result owner_result;
	struct vmm_startup_entry_runtime_result owner_runtime;
	uint64_t pending_event, vmcb_pa;
	int error, handled;
	uint16_t ldt_sel;
	bool entered_guest, migrated, nested, l0_vintr;

	vcpu = vcpui;
	/* A running guest must never observe a changed SVM CPUID model. */
	vcpu->nested_config_locked = true;
	if (vcpu->nested_poisoned ||
	    (vcpu->nested_active && vcpu->nested_pending.kind !=
	    SVM_NESTED_INSTRUCTION_NONE))
		return (EPROTO);
	svm_sc = vcpu->sc;
	nested = vcpu->nested_active;
	state = nested ? &vcpu->nested_vmcb02->state :
	    svm_get_vmcb_state(vcpu);
	ctrl = nested ? &vcpu->nested_vmcb02->ctrl :
	    svm_get_vmcb_ctrl(vcpu);
	vmexit = vm_exitinfo(vcpu->vcpu);
	vlapic = vm_lapic(vcpu->vcpu);

	gctx = svm_get_guest_regctx(vcpu);
	vmcb_pa = nested ? vtophys(vcpu->nested_vmcb02) : vcpu->vmcb_pa;
	run_pmap = nested ?
	    svm_nested_npt_root_pmap(vcpu->nested_npt02) : pmap;
	if (run_pmap == NULL)
		return (EPROTO);

	migrated = vcpu->lastcpu != curcpu;
	if (migrated) {
		/*
		 * Force new ASID allocation by invalidating the generation.
		 */
		vcpu->asid.gen = 0;
		vcpu->nested_asid.gen = 0;

		/*
		 * Invalidate the VMCB state cache by marking all fields dirty.
		 */
		svm_set_dirty(vcpu, 0xffffffff);

	}

	error = 0;
	svm_msr_guest_enter(vcpu);

	/* Update Guest RIP */
	state->rip = rip;

	do {
		irq_window = (struct svm_nested_irq_window){ 0 };
		/*
		 * Disable global interrupts to guarantee atomicity during
		 * loading of guest state. This includes not only the state
		 * loaded by the "vmrun" instruction but also software state
		 * maintained by the hypervisor: suspended and rendezvous
		 * state, NPT generation number, vlapic interrupts etc.
		 */
		disable_gintr();

		if (vcpu_suspended(evinfo)) {
			enable_gintr();
			vm_exit_suspended(vcpu->vcpu, state->rip);
			if (entry_owner != NULL)
				error = vmm_startup_entry_owner_software_exit(entry_owner,
				    &owner_result);
			break;
		}

		if (vcpu_rendezvous_pending(vcpu->vcpu, evinfo)) {
			enable_gintr();
			vm_exit_rendezvous(vcpu->vcpu, state->rip);
			if (entry_owner != NULL)
				error = vmm_startup_entry_owner_software_exit(entry_owner,
				    &owner_result);
			break;
		}

		if (vcpu_reqidle(evinfo)) {
			enable_gintr();
			vm_exit_reqidle(vcpu->vcpu, state->rip);
			if (entry_owner != NULL)
				error = vmm_startup_entry_owner_software_exit(entry_owner,
				    &owner_result);
			break;
		}

		/* We are asked to give the cpu by scheduler. */
		if (vcpu_should_yield(vcpu->vcpu)) {
			enable_gintr();
			vm_exit_astpending(vcpu->vcpu, state->rip);
			if (entry_owner != NULL)
				error = vmm_startup_entry_owner_software_exit(entry_owner,
				    &owner_result);
			break;
		}

		if (vcpu_debugged(vcpu->vcpu)) {
			enable_gintr();
			vm_exit_debug(vcpu->vcpu, state->rip);
			if (entry_owner != NULL)
				error = vmm_startup_entry_owner_software_exit(entry_owner,
				    &owner_result);
			break;
		}

		/*
		 * A pvclock MSR write emulated on the previous iteration
		 * deferred its guest-page publish; return to vm_run() so it
		 * can commit outside the critical section before the guest
		 * runs again.
		 */
		if (vpvclock_pending(vcpu->vcpu)) {
			enable_gintr();
			vm_exit_pvclock(vcpu->vcpu, state->rip);
			if (entry_owner != NULL)
				error = vmm_startup_entry_owner_software_exit(entry_owner,
				    &owner_result);
			break;
		}

		if (nested) {
			/* A userspace RIP change ends the old L2 interrupt shadow. */
			if (vcpu->nextrip != state->rip)
				ctrl->intr_shadow = 0;
			pending_event = svm_nested_pending_event(vcpu, vlapic);
			if (pending_event != 0) {
				vcpu->nested_pending.kind =
				    SVM_NESTED_L2_PENDING_EVENT;
				vmexit->exitcode = VM_EXITCODE_VMM_INTERNAL;
				vmexit->rip = state->rip;
				vmexit->inst_length = 0;
				enable_gintr();
				if (entry_owner != NULL) {
					error =
					    vmm_startup_entry_owner_software_exit(
					    entry_owner, &owner_result);
					if (error != 0)
						vcpu->nested_pending.kind =
						    SVM_NESTED_INSTRUCTION_NONE;
				}
				break;
			}
		}

		/*
		 * #VMEXIT resumes the host with the guest LDTR, so
		 * save the current LDT selector so it can be restored
		 * after an exit.  The userspace hypervisor probably
		 * doesn't use a LDT, but save and restore it to be
		 * safe.
		 */
		ldt_sel = sldt();

		if (!nested)
			svm_inj_interrupts(svm_sc, vcpu, vlapic);

		/*
		 * Check the pmap generation and the ASID generation to
		 * ensure that the vcpu does not use stale TLB mappings.
		 */
		if (nested)
			svm_pmap_activate_context(vcpu, run_pmap, ctrl,
			    &vcpu->nested_asid, &vcpu->nested_eptgen, false);
		else
			svm_pmap_activate(vcpu, run_pmap);

		if (nested)
			ctrl->vmcb_clean = 0;
		else {
			ctrl->vmcb_clean = vmcb_clean & ~vcpu->dirty;
			vcpu->dirty = 0;
		}
		SVM_CTR1(vcpu, "vmcb clean %#x", ctrl->vmcb_clean);

		/* Launch Virtual Machine. */
		SVM_CTR1(vcpu, "Resume execution at %#lx", state->rip);
		if (entry_owner != NULL) {
			error = vcpu_startup_entry_owner_guard_before_attempt(vcpu->vcpu,
			    entry_owner, &owner_runtime);
			if (error != 0 || owner_runtime.action !=
			    VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST) {
				svm_pmap_deactivate(run_pmap);
				/*
				 * ctrl->vmcb_clean and dirty were prepared for a VMRUN
				 * that did not happen.  Do not let the next real entry
				 * describe those unconsumed VMCB changes as hardware-clean.
				 */
				svm_set_dirty(vcpu, 0xffffffff);
				enable_gintr();
				if (error == 0 &&
				    vmm_startup_entry_owner_resolve_deferred(entry_owner,
				    0, &owner_result) != 0)
					panic("%s: invalid declined SVM startup owner",
					    __func__);
				break;
			}
		}
		if (nested) {
			svm_nested_inj_intinfo(vcpu);
			svm_nested_inj_nmi(vcpu);
			svm_nested_inj_irq(svm_sc, vcpu, vlapic, &irq_window);
			SDT_PROBE5(vmm, svm, nested, entry, svm_sc,
			    vcpu->vcpuid, vcpu->nested_vmcb12_gpa,
			    vcpu->nested_npt12_root_gpa, ctrl->asid);
		}
		svm_dr_enter_guest(gctx);
		svm_launch(vmcb_pa, gctx, get_pcpu());
		svm_dr_leave_guest(gctx);
		/* An invalid VMCB returns from VMRUN without guest execution. */
		entered_guest = ctrl->exitcode != VMCB_EXIT_INVALID;
		if (!entered_guest)
			svm_set_dirty(vcpu, 0xffffffff);
		if (entry_owner != NULL) {
			if (entered_guest) {
				if (vmm_startup_entry_owner_commit_attempt(
				    entry_owner) != 0)
					panic("%s: SVM startup owner did not commit entry",
					    __func__);
			} else if (vmm_startup_entry_owner_abort_attempt(
			    entry_owner, &owner_result) != 0)
				panic("%s: SVM startup owner did not abort entry",
				    __func__);
		}
		l0_vintr = nested && irq_window.active &&
		    ctrl->exitcode == VMCB_EXIT_VINTR;
		if (nested)
			svm_nested_irq_window_restore(ctrl, &irq_window);
		if (nested && entered_guest &&
		    ctrl->exitcode != VMCB_EXIT_SHUTDOWN)
			svm_nested_vnmi_sync(vcpu);
		/*
		 * Publish CPU residency only after guest execution is proved.
		 * The pre-entry lifecycle checks above can return without entering
		 * the guest; treating those paths as a migration suppresses the
		 * mandatory ASID/cache refresh on their next real entry.
		 */
		if (migrated && entered_guest) {
			vcpu->lastcpu = curcpu;
			vmm_stat_incr(vcpu->vcpu, VCPU_MIGRATIONS, 1);
			migrated = false;
		}

		svm_pmap_deactivate(run_pmap);

		/*
		 * The host GDTR and IDTR is saved by VMRUN and restored
		 * automatically on #VMEXIT. However, the host TSS needs
		 * to be restored explicitly.
		 */
		restore_host_tss();

		/* Restore host LDTR. */
		lldt(ldt_sel);

		/* #VMEXIT disables interrupts so re-enable them here. */
		enable_gintr();

		/* Hardware does not define saved state after SHUTDOWN. */
		if (ctrl->exitcode != VMCB_EXIT_SHUTDOWN)
			vcpu->nextrip = state->rip;
		else if (nested)
			vcpu->nextrip = vcpu->nested_l1_next_rip;
		if (nested && entered_guest) {
			/* L2 bypasses svm_vmexit(), which owns the L1 counters. */
			vmm_stat_incr(vcpu->vcpu, VMEXIT_COUNT, 1);
			if (ctrl->exitcode == VMCB_EXIT_VINTR)
				vmm_stat_incr(vcpu->vcpu, VMEXIT_VINTR, 1);
			else if (ctrl->exitcode == VMCB_EXIT_INTR)
				vmm_stat_incr(vcpu->vcpu, VMEXIT_EXTINT, 1);
			else if (ctrl->exitcode >= 0x40 &&
			    ctrl->exitcode < 0x60)
				vmm_stat_incr(vcpu->vcpu, VMEXIT_EXCEPTION, 1);
			SDT_PROBE5(vmm, svm, nested, vmexit, svm_sc,
			    vcpu->vcpuid, vcpu->nested_vmcb12_gpa,
			    ctrl->exitcode, ctrl->exitinfo1);
		}

		/* Handle #VMEXIT and if required return to user space. */
		if (l0_vintr)
			handled = 1;
		else if (nested) {
			/*
			 * L2 EXITINTINFO belongs to nested replay or VMCB12
			 * writeback.  Its V_TPR may be L1's virtual TPR.  The
			 * ordinary svm_vmexit() path publishes both into L0 state.
			 */
			if (vcpu->nested_pending.kind !=
			    SVM_NESTED_INSTRUCTION_NONE)
				panic("%s: nested exit already pending", __func__);
			vcpu->nested_pending.kind = SVM_NESTED_L2_EXIT;
			vmexit->exitcode = VM_EXITCODE_VMM_INTERNAL;
			vmexit->rip = ctrl->exitcode == VMCB_EXIT_SHUTDOWN ?
			    vcpu->nested_l1_next_rip : state->rip;
			vmexit->inst_length = 0;
			handled = 0;
		} else
			handled = svm_vmexit(svm_sc, vcpu, vmexit);
		if (!nested && handled && ctrl->exitcode == VMCB_EXIT_STGI &&
		    (vcpu->startup_claim_phase == SVM_STARTUP_CLAIM_HELD ||
		    vcpu->startup_claim_phase ==
		    SVM_STARTUP_CLAIM_INIT_REFLECTED) &&
		    vcpu->startup_claim.kind == VMM_STARTUP_EVENT_INIT &&
		    vcpu->nested_gif) {
			/* STGI opened the pending INIT; dispatch before another entry. */
			vcpu->nested_pending.kind = SVM_NESTED_INIT_GIF_RECHECK;
			vmexit->exitcode = VM_EXITCODE_VMM_INTERNAL;
			vmexit->rip = state->rip;
			vmexit->inst_length = 0;
			vcpu->nextrip = state->rip;
			vm_set_nextrip(vcpu->vcpu, state->rip);
			handled = 0;
		}
		if (entry_owner != NULL && entered_guest) {
			error = vmm_startup_entry_owner_guard_after(entry_owner,
			    handled != 0, 0, handled != 0 ? NULL : &owner_result);
			if (error != 0)
				panic("%s: invalid startup owner after VMRUN", __func__);
		}
	} while (handled);

	svm_msr_guest_exit(vcpu);

	return (error);
}

static void
svm_vcpu_cleanup(void *vcpui)
{
	struct svm_vcpu *vcpu = vcpui;

	KASSERT(vcpu->startup_claim_phase == SVM_STARTUP_CLAIM_EMPTY,
	    ("%s: live startup claim", __func__));
	free(vcpu->vmcb, M_SVM);
	free(vcpu->snapshot_vmcb, M_SVM);
	free(vcpu->nested_vmcb12, M_SVM);
	free(vcpu->nested_vmcb02, M_SVM);
	svm_nested_npt_root_destroy(vcpu->nested_npt02);
	free(vcpu, M_SVM);
}

/* GDTR and IDTR have no selector in a VMCB; the common adapter uses zero. */
static int
svm_startup_raw_getreg(void *arg, enum vm_reg_name reg, uint64_t *value)
{

	if (reg == VM_REG_GUEST_GDTR || reg == VM_REG_GUEST_IDTR) {
		*value = 0;
		return (0);
	}
	return (svm_getreg(arg, reg, value));
}

static int
svm_startup_raw_setreg(void *arg, enum vm_reg_name reg, uint64_t value)
{

	if (reg == VM_REG_GUEST_GDTR || reg == VM_REG_GUEST_IDTR)
		return (value == 0 ? 0 : EINVAL);
	return (svm_setreg(arg, reg, value));
}

static int
svm_startup_raw_getdesc(void *arg, enum vm_reg_name reg,
    struct seg_desc *desc)
{

	return (svm_getdesc(arg, reg, desc));
}

static int
svm_startup_raw_setdesc(void *arg, enum vm_reg_name reg,
    const struct seg_desc *desc)
{
	struct seg_desc candidate;

	candidate = *desc;
	return (svm_setdesc(arg, reg, &candidate));
}

struct svm_startup_l0_binding {
	struct svm_vcpu *vcpu;
	struct vmm_x86_startup_backend backend;
	struct svm_nested_npt_root *retired_npt02;
};

static int
svm_startup_getreg(void *arg, enum vmm_x86_startup_register reg,
    uint64_t *value)
{
	struct svm_startup_l0_binding *binding = arg;

	return (vmm_x86_startup_backend_getreg(&binding->backend, reg, value));
}

static int
svm_startup_setreg(void *arg, enum vmm_x86_startup_register reg,
    uint64_t value)
{
	struct svm_startup_l0_binding *binding = arg;

	return (vmm_x86_startup_backend_setreg(&binding->backend, reg, value));
}

static int
svm_startup_getdesc(void *arg, enum vmm_x86_startup_descriptor desc,
    struct vmm_x86_startup_desc *value)
{
	struct svm_startup_l0_binding *binding = arg;

	return (vmm_x86_startup_backend_getdesc(&binding->backend, desc,
	    value));
}

static int
svm_startup_setdesc(void *arg, enum vmm_x86_startup_descriptor desc,
    const struct vmm_x86_startup_desc *value)
{
	struct svm_startup_l0_binding *binding = arg;

	return (vmm_x86_startup_backend_setdesc(&binding->backend, desc,
	    value));
}

static int
svm_startup_event_capture(void *arg, struct vmm_event_state *state)
{
	struct svm_startup_l0_binding *binding = arg;

	return (vm_event_state_capture(binding->vcpu->vcpu, state));
}

static int
svm_startup_event_compare_clear(void *arg,
    const struct vmm_event_state *state)
{
	struct svm_startup_l0_binding *binding = arg;

	return (vm_event_state_compare_clear(binding->vcpu->vcpu, state));
}

static const struct vmm_x86_startup_backend_ops svm_startup_backend_ops = {
	.getreg = svm_startup_raw_getreg,
	.setreg = svm_startup_raw_setreg,
	.getdesc = svm_startup_raw_getdesc,
	.setdesc = svm_startup_raw_setdesc,
};

static const struct vmm_x86_startup_machine_ops svm_startup_machine_ops = {
	.getreg = svm_startup_getreg,
	.setreg = svm_startup_setreg,
	.getdesc = svm_startup_getdesc,
	.setdesc = svm_startup_setdesc,
	.event_capture = svm_startup_event_capture,
	.event_compare_clear = svm_startup_event_compare_clear,
};

static void
svm_startup_reset_nested(void *arg)
{
	struct svm_startup_l0_binding *binding = arg;
	struct svm_vcpu *vcpu = binding->vcpu;

	KASSERT(!vcpu->nested_active &&
	    vcpu->nested_pending.kind == SVM_NESTED_INSTRUCTION_NONE,
	    ("%s: nested execution reached INIT finalizer", __func__));
	/* Detach a live L2 root without sleeping in the no-fail finalizer. */
	binding->retired_npt02 = vcpu->nested_npt02;
	vcpu->nested_npt02 = NULL;
	svm_nested_msr_init_signal(&vcpu->nested_msr);
	bzero(vcpu->nested_vmcb12, sizeof(*vcpu->nested_vmcb12));
	bzero(vcpu->nested_vmcb02, sizeof(*vcpu->nested_vmcb02));
	bzero(vcpu->nested_vnmi_gpas, sizeof(vcpu->nested_vnmi_gpas));
	vcpu->nested_vmcb12_gpa = 0;
	vcpu->nested_npt12_root_gpa = 0;
	vcpu->nested_l1_next_rip = 0;
	vcpu->nested_gif = true;
	vcpu->vmcb->state.cpl = 0;
}

static void
svm_startup_reset_lapic(void *arg)
{
	struct svm_startup_l0_binding *binding = arg;

	vlapic_reset_startup(binding->vcpu->vcpu);
}

static void
svm_startup_retire_translations(void *arg)
{
	struct svm_startup_l0_binding *binding = arg;
	struct svm_vcpu *vcpu = binding->vcpu;

	vcpu->asid.gen = 0;
	vcpu->nested_asid.gen = 0;
	vcpu->eptgen = 0;
	vcpu->nested_eptgen = 0;
	svm_set_dirty(vcpu, 0xffffffff);
}

static void
svm_startup_set_nextrip(void *arg, uint64_t nextrip)
{
	struct svm_startup_l0_binding *binding = arg;

	binding->vcpu->nextrip = nextrip;
	vm_set_nextrip(binding->vcpu->vcpu, nextrip);
}

static void
svm_startup_publish_wait(void *arg, bool waiting)
{
	struct svm_startup_l0_binding *binding = arg;
	cpuset_t targets, waiters;

	CPU_ZERO(&targets);
	CPU_ZERO(&waiters);
	CPU_SET(binding->vcpu->vcpuid, &targets);
	if (waiting)
		CPU_SET(binding->vcpu->vcpuid, &waiters);
	vm_publish_startup_wait(vcpu_vm(binding->vcpu->vcpu), &targets,
	    &waiters);
}

static const struct vmm_x86_startup_finalizer_ops
svm_startup_finalizer_ops = {
	.reset_nested = svm_startup_reset_nested,
	.reset_lapic = svm_startup_reset_lapic,
	.retire_translation_residency = svm_startup_retire_translations,
	.set_nextrip = svm_startup_set_nextrip,
	.publish_startup_wait = svm_startup_publish_wait,
};

static int
svm_startup_l0_machine_apply(struct svm_vcpu *vcpu,
    const struct vmm_startup_event_claim *claim,
    struct vmm_x86_startup_transaction_result *result,
    struct svm_nested_npt_root **retired_npt02)
{
	struct svm_startup_l0_binding binding;
	struct vmm_x86_startup_finalizer finalizer;
	struct vmm_x86_startup_finalizer_plan plan;
	struct vmm_x86_startup_transaction_input input;
	uint64_t rax, rbx, rcx, rdx;
	int error;

	if (retired_npt02 == NULL)
		return (EINVAL);
	*retired_npt02 = NULL;
	/* Preparation failures are safe to abort before machine_execute(). */
	result->rollback_complete = 1;
	bzero(&binding, sizeof(binding));
	bzero(&finalizer, sizeof(finalizer));
	bzero(&input, sizeof(input));
	input.kind = claim->kind;
	input.vector = claim->vector;
	input.bootstrap_processor =
	    (vlapic_get_apicbase(vm_lapic(vcpu->vcpu)) & APICBASE_BSP) != 0;
	error = vmm_x86_startup_finalizer_plan(&input, &plan);
	if (error != 0)
		return (error);
	binding.vcpu = vcpu;
	error = vmm_x86_startup_backend_init(&binding.backend,
	    &svm_startup_backend_ops, vcpu);
	if (error != 0)
		return (error);
	rax = CPUID_0000_0001;
	rbx = rcx = rdx = 0;
	error = x86_emulate_cpuid(vcpu->vcpu, &rax, &rbx, &rcx, &rdx);
	if (error != 1)
		return (EPROTO);
	if (rax > UINT32_MAX)
		return (EPROTO);
	error = vmm_x86_startup_finalizer_init(&svm_startup_finalizer_ops,
	    &binding, &plan, &finalizer);
	if (error != 0)
		return (error);
	error = vmm_x86_startup_machine_execute(&input, (uint32_t)rax,
	    &svm_startup_machine_ops, &binding, &finalizer, result);
	*retired_npt02 = binding.retired_npt02;
	return (error);
}

static bool
svm_startup_claim_empty(const struct vmm_startup_event_claim *claim)
{

	return (claim->owner_id == 0 && claim->claim_id == 0 &&
	    claim->state_cookie == 0 && claim->storage_cookie == 0 &&
	    claim->vcpuid == 0 && claim->kind == 0 && claim->vector == 0 &&
	    claim->active == 0 && claim->reserved8 == 0 &&
	    claim->reserved32 == 0);
}

static int
svm_vcpu_event_cleanup_check(void *vcpui)
{
	struct svm_vcpu *vcpu = vcpui;

	if (vcpu == NULL ||
	    vcpu->startup_claim_phase == SVM_STARTUP_CLAIM_POISONED)
		return (EPROTO);
	if (vcpu->startup_claim_phase == SVM_STARTUP_CLAIM_EMPTY)
		return (svm_startup_claim_empty(&vcpu->startup_claim) ?
		    0 : EPROTO);
	if (vcpu->startup_claim_phase != SVM_STARTUP_CLAIM_HELD &&
	    vcpu->startup_claim_phase != SVM_STARTUP_CLAIM_INIT_REFLECTED &&
	    vcpu->startup_claim_phase != SVM_STARTUP_CLAIM_FINISH_PENDING)
		return (EPROTO);
	if (vcpu->startup_claim_phase == SVM_STARTUP_CLAIM_INIT_REFLECTED &&
	    vcpu->startup_claim.kind != VMM_STARTUP_EVENT_INIT)
		return (EPROTO);
	return (vcpu_startup_event_claim_check(vcpu->vcpu,
	    &vcpu->startup_claim));
}

static int
svm_startup_claim_release(struct svm_vcpu *vcpu, bool committed)
{
	int error;

	error = committed ? vcpu_startup_event_claim_finish(vcpu->vcpu,
	    &vcpu->startup_claim) : vcpu_startup_event_claim_abort(vcpu->vcpu,
	    &vcpu->startup_claim);
	if (error == 0 && !svm_startup_claim_empty(&vcpu->startup_claim)) {
		vcpu->startup_claim_phase = SVM_STARTUP_CLAIM_POISONED;
		return (EPROTO);
	}
	if (error == 0)
		vcpu->startup_claim_phase = SVM_STARTUP_CLAIM_EMPTY;
	return (error);
}

static int
svm_startup_l0_preflight(struct svm_vcpu *vcpu,
    const struct vmm_startup_event_claim *claim, bool discard_l2)
{
	struct vmm_startup_entry_snapshot snapshot;
	int error;

	if (vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN ||
	    (claim->kind != VMM_STARTUP_EVENT_INIT &&
	    claim->kind != VMM_STARTUP_EVENT_SIPI) ||
	    (claim->kind == VMM_STARTUP_EVENT_INIT && claim->vector != 0))
		return (EINVAL);
	if (claim->kind == VMM_STARTUP_EVENT_SIPI) {
		error = vcpu_startup_entry_observation(vcpu->vcpu,
		    &snapshot, NULL);
		if (error != 0)
			return (error);
		if (snapshot.waiting == 0)
			return (EBUSY);
	}
	if (vcpu->nested_poisoned)
		return (EPROTO);
	if (!svm_nested_msr_state_valid(&vcpu->nested_msr,
	    svm_nested_physical_width(vm_mtrr_maxphyaddr(cpu_maxphyaddr))))
		return (EPROTO);
	/* L1 GIF is clear during L2; outside L2 it holds INIT pending. */
	if (discard_l2) {
		if (claim->kind != VMM_STARTUP_EVENT_INIT ||
		    !vcpu->nested_active || vcpu->nested_gif ||
		    vcpu->nested_npt02 == NULL ||
		    vcpu->nested_vmcb12_gpa == 0 ||
		    vcpu->nested_vmcb12 == NULL ||
		    vcpu->nested_vmcb02 == NULL)
			return (EPROTO);
		if ((vcpu->nested_vmcb12->ctrl.intercept[
		    VMCB_CTRL1_INTCPT] & VMCB_INTCPT_INIT) != 0)
			return (EINVAL);
	} else if (vcpu->nested_active || !vcpu->nested_gif)
		return (EBUSY);
	if (vcpu->nested_pending.kind != SVM_NESTED_INSTRUCTION_NONE ||
	    vcpu->nested_debug_step_l2 ||
	    (vcpu->caps & ((1 << VM_CAP_MASK_HWINTR) |
	    (1 << VM_CAP_RFLAGS_TF))) != 0 ||
	    vcpu->dbg.rflags_tf != 0 || vcpu->dbg.popf_sstep ||
	    vcpu->dbg.pushf_sstep)
		return (EBUSY);
	return (0);
}

static void
svm_startup_l0_prepare(struct svm_vcpu *vcpu,
    const struct vmm_startup_event_claim *claim)
{

	if (claim->kind != VMM_STARTUP_EVENT_INIT)
		return;
	/*
	 * NPT02 is a derived cache and can be discarded after preflight even if
	 * the startup transaction subsequently rolls back.  vmspace teardown may
	 * block, so it must not run in the irreversible finalizer.  Active L2
	 * retains its root until commit, then detaches and destroys it outside
	 * the finalizer.
	 */
	svm_nested_npt_root_destroy(vcpu->nested_npt02);
	vcpu->nested_npt02 = NULL;
	/* A failed INIT may enter L2 again with a newly allocated root. */
	vcpu->nested_asid.gen = 0;
	vcpu->nested_eptgen = 0;
}

/* Reflect an L1-requested virtual INIT while L2 is the frozen run owner. */
static int
svm_startup_l2_init_reflect(struct svm_vcpu *vcpu)
{
	struct vmcb_ctrl before;
	uint64_t vnmi_before[SVM_NESTED_VNMI_SLOTS];
	struct vmcb_ctrl *ctrl;
	int error;

	if (vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN ||
	    vcpu->nested_poisoned)
		return (EPROTO);
	if (!vcpu->nested_active || vcpu->nested_npt02 == NULL ||
	    vcpu->nested_gif ||
	    vcpu->nested_vmcb12_gpa == 0 || vcpu->nested_vmcb12 == NULL ||
	    vcpu->nested_vmcb02 == NULL)
		return (EPROTO);
	if (vcpu->nested_pending.kind != SVM_NESTED_INSTRUCTION_NONE)
		return (EBUSY);
	if ((vcpu->nested_vmcb12->ctrl.intercept[VMCB_CTRL1_INTCPT] &
	    VMCB_INTCPT_INIT) == 0)
		return (EOPNOTSUPP);
	ctrl = &vcpu->nested_vmcb02->ctrl;
	if (((ctrl->eventinj | ctrl->exitintinfo) & VMCB_EVENTINJ_VALID) != 0)
		return (EBUSY);
	before = *ctrl;
	bcopy(vcpu->nested_vnmi_gpas, vnmi_before, sizeof(vnmi_before));
	ctrl->exitcode = VMCB_EXIT_INIT;
	ctrl->exitinfo1 = 0;
	ctrl->exitinfo2 = 0;
	ctrl->exitintinfo = 0;
	/* INIT is asynchronous; it has no architectural next instruction RIP. */
	ctrl->nrip = 0;
	ctrl->inst_len = 0;
	bzero(ctrl->inst_bytes, sizeof(ctrl->inst_bytes));
	error = svm_nested_l2_reflect(vcpu);
	if (error != 0) {
		*ctrl = before;
		bcopy(vnmi_before, vcpu->nested_vnmi_gpas,
		    sizeof(vnmi_before));
	} else
		SDT_PROBE5(vmm, svm, nested, vmexit, vcpu->sc,
		    vcpu->vcpuid, vcpu->nested_vmcb12_gpa, VMCB_EXIT_INIT, 0);
	return (error);
}

static bool
svm_startup_kernel_actions_ready(void)
{

	return (kernel_startup_experimental == 1);
}

static int
svm_vcpu_startup_event_step(void *vcpui,
    enum vmm_startup_dispatch_result *result)
{
	struct vmm_x86_startup_transaction_result machine_result;
	struct vmm_startup_entry_snapshot snapshot;
	struct svm_nested_npt_root *retired_npt02;
	struct svm_vcpu *vcpu = vcpui;
	bool discard_l2, pending_init_unmasked, unmasked_init;
	int error, machine_error;

	if (vcpu == NULL || result == NULL)
		return (EINVAL);
	/* A startup claim is owned by this frozen target for the whole step. */
	if (vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	if (vcpu->startup_claim_phase == SVM_STARTUP_CLAIM_POISONED)
		return (EPROTO);
	pending_init_unmasked = false;
	if (vcpu->startup_claim_phase == SVM_STARTUP_CLAIM_FINISH_PENDING) {
		error = svm_startup_claim_release(vcpu, true);
		if (error == 0)
			*result = VMM_STARTUP_DISPATCH_CONSUMED;
		return (error);
	}
	if (vcpu->startup_claim_phase == SVM_STARTUP_CLAIM_INIT_REFLECTED) {
		/* AMD leaves intercepted INIT pending while L1 GIF is clear. */
		if (vcpu->startup_claim.kind != VMM_STARTUP_EVENT_INIT ||
		    vcpu_startup_event_claim_check(vcpu->vcpu,
		    &vcpu->startup_claim) != 0)
			return (EPROTO);
		if (!vcpu->nested_active && !vcpu->nested_gif) {
			*result = VMM_STARTUP_DISPATCH_RETAINED;
			return (0);
		}
		/* VMRUN gives L2 GIF=1 even while the L1 host GIF is clear. */
		vcpu->startup_claim_phase = SVM_STARTUP_CLAIM_HELD;
		pending_init_unmasked = true;
	}
	if (vcpu->startup_claim_phase == SVM_STARTUP_CLAIM_EMPTY) {
		error = vcpu_startup_event_claim_begin(vcpu->vcpu,
		    &vcpu->startup_claim);
		if (error == ENOENT) {
			*result = VMM_STARTUP_DISPATCH_IDLE;
			return (0);
		}
		if (error != 0)
			return (error);
		vcpu->startup_claim_phase = SVM_STARTUP_CLAIM_HELD;
	}
	if (vcpu->startup_claim_phase != SVM_STARTUP_CLAIM_HELD)
		return (EPROTO);
	error = vcpu_startup_event_claim_check(vcpu->vcpu,
	    &vcpu->startup_claim);
	if (error != 0)
		return (error);
	if (vcpu->startup_claim.vcpuid != (uint32_t)vcpu->vcpuid ||
	    (vcpu->startup_claim.kind != VMM_STARTUP_EVENT_INIT &&
	    vcpu->startup_claim.kind != VMM_STARTUP_EVENT_SIPI) ||
	    (vcpu->startup_claim.kind == VMM_STARTUP_EVENT_INIT &&
	    vcpu->startup_claim.vector != 0))
		return (EPROTO);
	/* Even an ignored SIPI must not consume a claim over corrupt SVM state. */
	if (vcpu->nested_poisoned ||
	    !svm_nested_msr_state_valid(&vcpu->nested_msr,
	    svm_nested_physical_width(vm_mtrr_maxphyaddr(cpu_maxphyaddr))))
		return (EPROTO);
	if (vcpu->startup_claim.kind == VMM_STARTUP_EVENT_SIPI) {
		error = vcpu_startup_entry_observation(vcpu->vcpu,
		    &snapshot, NULL);
		if (error != 0)
			return (error);
		if (snapshot.waiting == 0) {
			/* A SIPI cannot restart an AP that is already running. */
			vcpu->startup_claim_phase =
			    SVM_STARTUP_CLAIM_FINISH_PENDING;
			error = svm_startup_claim_release(vcpu, true);
			if (error == 0)
				*result = VMM_STARTUP_DISPATCH_CONSUMED;
			return (error);
		}
		if (vcpu->nested_active)
			return (EPROTO);
	}
	unmasked_init = vcpu->startup_claim.kind == VMM_STARTUP_EVENT_INIT &&
	    (vcpu->nested_active || vcpu->nested_gif);
	if (vcpu->startup_claim.kind == VMM_STARTUP_EVENT_INIT &&
	    !vcpu->nested_active && vcpu->nested_gif &&
	    (vcpu->nested_msr.vm_cr & VM_CR_R_INIT) != 0) {
		/* A redirected, unmasked INIT becomes #SX(error code 1). */
		if (vcpu->nested_poisoned ||
		    !svm_nested_msr_state_valid(&vcpu->nested_msr,
		    svm_nested_physical_width(
		    vm_mtrr_maxphyaddr(cpu_maxphyaddr))))
			return (EPROTO);
		if (vcpu->nested_pending.kind != SVM_NESTED_INSTRUCTION_NONE)
			return (EBUSY);
		error = vm_inject_exception(vcpu->vcpu, IDT_SX, 1, 1, 0);
		if (error != 0) {
			if (pending_init_unmasked)
				vcpu->startup_claim_phase =
				    SVM_STARTUP_CLAIM_INIT_REFLECTED;
			return (error);
		}
		vcpu->startup_claim_phase = SVM_STARTUP_CLAIM_FINISH_PENDING;
		error = svm_startup_claim_release(vcpu, true);
		if (error == 0)
			*result = VMM_STARTUP_DISPATCH_CONSUMED;
		return (error);
	}
	discard_l2 = vcpu->nested_active;
	if (discard_l2 && vcpu->nested_vmcb12 != NULL &&
	    (vcpu->nested_vmcb12->ctrl.intercept[VMCB_CTRL1_INTCPT] &
	    VMCB_INTCPT_INIT) != 0) {
		if (vcpu->startup_claim.kind != VMM_STARTUP_EVENT_INIT)
			return (EOPNOTSUPP);
		error = svm_startup_l2_init_reflect(vcpu);
		if (error == EBUSY) {
			*result = VMM_STARTUP_DISPATCH_RETAINED;
			return (0);
		}
		if (error != 0)
			return (error);
		vcpu->startup_claim_phase = SVM_STARTUP_CLAIM_INIT_REFLECTED;
		*result = VMM_STARTUP_DISPATCH_RETAINED;
		return (0);
	}
	if (discard_l2 && vcpu->startup_claim.kind != VMM_STARTUP_EVENT_INIT)
		return (EOPNOTSUPP);
	/* Without L1's INIT intercept, apply R_INIT or reset the vCPU. */
	error = svm_startup_l0_preflight(vcpu, &vcpu->startup_claim,
	    discard_l2);
	if (error == EBUSY) {
		if (pending_init_unmasked) {
			vcpu->startup_claim_phase =
			    SVM_STARTUP_CLAIM_INIT_REFLECTED;
			return (EBUSY);
		}
		if (unmasked_init)
			return (EBUSY);
		*result = VMM_STARTUP_DISPATCH_RETAINED;
		return (0);
	}
	if (error != 0 && unmasked_init) {
		if (pending_init_unmasked)
			vcpu->startup_claim_phase =
			    SVM_STARTUP_CLAIM_INIT_REFLECTED;
		return (error);
	}
	if (error != 0)
		return (svm_startup_claim_release(vcpu, false) == 0 ? error :
		    EPROTO);
	if (discard_l2 &&
	    (vcpu->nested_msr.vm_cr & VM_CR_R_INIT) != 0) {
		struct vmcb_ctrl *ctrl;

		ctrl = &vcpu->nested_vmcb02->ctrl;
		if (((ctrl->eventinj | ctrl->exitintinfo) &
		    VMCB_EVENTINJ_VALID) != 0) {
			*result = VMM_STARTUP_DISPATCH_RETAINED;
			return (0);
		}
		error = svm_nested_l2_synthetic_exception(vcpu, IDT_SX,
		    true, 1);
		if (error != 0)
			return (error);
		vcpu->startup_claim_phase = SVM_STARTUP_CLAIM_FINISH_PENDING;
		error = svm_startup_claim_release(vcpu, true);
		if (error == 0)
			*result = VMM_STARTUP_DISPATCH_CONSUMED;
		return (error);
	}
	if (discard_l2) {
		/* Select VMCB01 for the architectural reset, preserving L2 on abort. */
		vcpu->nested_active = false;
	} else
		svm_startup_l0_prepare(vcpu, &vcpu->startup_claim);
	bzero(&machine_result, sizeof(machine_result));
	retired_npt02 = NULL;
	machine_error = svm_startup_l0_machine_apply(vcpu,
	    &vcpu->startup_claim, &machine_result, &retired_npt02);
	if (machine_result.committed != 0) {
		if (discard_l2 && retired_npt02 == NULL) {
			vcpu->startup_claim_phase = SVM_STARTUP_CLAIM_POISONED;
			return (EPROTO);
		}
		svm_nested_npt_root_destroy(retired_npt02);
		vcpu->startup_claim_phase = SVM_STARTUP_CLAIM_FINISH_PENDING;
		error = svm_startup_claim_release(vcpu, true);
		if (error == 0)
			*result = VMM_STARTUP_DISPATCH_CONSUMED;
		return (error);
	}
	if (discard_l2)
		vcpu->nested_active = true;
	if (retired_npt02 != NULL) {
		svm_nested_npt_root_destroy(retired_npt02);
		vcpu->startup_claim_phase = SVM_STARTUP_CLAIM_POISONED;
		return (EPROTO);
	}
	if (machine_result.rollback_complete == 0 ||
	    machine_result.poisoned != 0 || machine_error == 0) {
		vcpu->startup_claim_phase = SVM_STARTUP_CLAIM_POISONED;
		return (machine_error != 0 ? machine_error : EPROTO);
	}
	if (unmasked_init) {
		if (pending_init_unmasked)
			vcpu->startup_claim_phase =
			    SVM_STARTUP_CLAIM_INIT_REFLECTED;
		return (machine_error);
	}
	error = svm_startup_claim_release(vcpu, false);
	return (error != 0 ? error : machine_error);
}

static int
svm_vcpu_event_cleanup(void *vcpui)
{
	struct svm_vcpu *vcpu = vcpui;
	int error;

	error = svm_vcpu_event_cleanup_check(vcpu);
	if (error != 0 || vcpu->startup_claim_phase == SVM_STARTUP_CLAIM_EMPTY)
		return (error);
	return (svm_startup_claim_release(vcpu,
	    vcpu->startup_claim_phase == SVM_STARTUP_CLAIM_FINISH_PENDING));
}

#define SVM_NESTED_STATE_SCHEMA_VERSION 2U

#ifdef BHYVE_SNAPSHOT
#define SVM_SNAPSHOT_VM_MAGIC "WASPSVM1"
#define SVM_SNAPSHOT_VM_HEADER_SIZE 12U
#define SVM_SNAPSHOT_VERSION SVM_NESTED_STATE_SCHEMA_VERSION
#define SVM_SNAPSHOT_VCPU_HEADER_SIZE 48U
#define SVM_SNAPSHOT_F_EXPOSED 0x01U
#define SVM_SNAPSHOT_F_SVME 0x02U
#define SVM_SNAPSHOT_F_ACTIVE 0x04U
#define SVM_SNAPSHOT_F_GIF_CLEAR 0x08U

static void
svm_snapshot_restore_free(struct svm_snapshot_restore *stage)
{
	uint16_t i;

	if (stage == NULL)
		return;
	if (stage->vcpus != NULL) {
		for (i = 0; i < stage->maxcpus; i++) {
			if (stage->vcpus[i].nested_vmcb12 != NULL)
				explicit_bzero(stage->vcpus[i].nested_vmcb12,
				    sizeof(*stage->vcpus[i].nested_vmcb12));
			if (stage->vcpus[i].nested_vmcb02 != NULL)
				explicit_bzero(stage->vcpus[i].nested_vmcb02,
				    sizeof(*stage->vcpus[i].nested_vmcb02));
			free(stage->vcpus[i].nested_vmcb12, M_SVM);
			free(stage->vcpus[i].nested_vmcb02, M_SVM);
			svm_nested_npt_root_destroy(
			    stage->vcpus[i].nested_npt02);
		}
		explicit_bzero(stage->vcpus,
		    (size_t)stage->maxcpus * sizeof(*stage->vcpus));
		free(stage->vcpus, M_SVM);
	}
	explicit_bzero(stage, sizeof(*stage));
	free(stage, M_SVM);
}
#endif

static void
svm_cleanup(void *vmi)
{
	struct svm_softc *sc = vmi;

#ifdef BHYVE_SNAPSHOT
	svm_snapshot_restore_free(sc->snapshot_restore);
#endif
	free(sc->iopm_bitmap, M_SVM);
	free(sc->msr_bitmap, M_SVM);
	free(sc->nested_msr_bitmap, M_SVM);
	free(sc, M_SVM);
}

static register_t *
swctx_regptr(struct svm_regctx *regctx, int reg)
{

	switch (reg) {
	case VM_REG_GUEST_RBX:
		return (&regctx->sctx_rbx);
	case VM_REG_GUEST_RCX:
		return (&regctx->sctx_rcx);
	case VM_REG_GUEST_RDX:
		return (&regctx->sctx_rdx);
	case VM_REG_GUEST_RDI:
		return (&regctx->sctx_rdi);
	case VM_REG_GUEST_RSI:
		return (&regctx->sctx_rsi);
	case VM_REG_GUEST_RBP:
		return (&regctx->sctx_rbp);
	case VM_REG_GUEST_R8:
		return (&regctx->sctx_r8);
	case VM_REG_GUEST_R9:
		return (&regctx->sctx_r9);
	case VM_REG_GUEST_R10:
		return (&regctx->sctx_r10);
	case VM_REG_GUEST_R11:
		return (&regctx->sctx_r11);
	case VM_REG_GUEST_R12:
		return (&regctx->sctx_r12);
	case VM_REG_GUEST_R13:
		return (&regctx->sctx_r13);
	case VM_REG_GUEST_R14:
		return (&regctx->sctx_r14);
	case VM_REG_GUEST_R15:
		return (&regctx->sctx_r15);
	case VM_REG_GUEST_DR0:
		return (&regctx->sctx_dr0);
	case VM_REG_GUEST_DR1:
		return (&regctx->sctx_dr1);
	case VM_REG_GUEST_DR2:
		return (&regctx->sctx_dr2);
	case VM_REG_GUEST_DR3:
		return (&regctx->sctx_dr3);
	default:
		return (NULL);
	}
}

static int
svm_getreg(void *vcpui, int ident, uint64_t *val)
{
	struct svm_vcpu *vcpu;
	struct vmcb *vmcb;
	register_t *reg;

	vcpu = vcpui;
	vmcb = vcpu->nested_active ? vcpu->nested_vmcb02 : vcpu->vmcb;

	if (ident == VM_REG_GUEST_INTR_SHADOW) {
		if (vcpu->nested_active) {
			*val = vmcb->ctrl.intr_shadow;
			return (0);
		}
		return (svm_get_intr_shadow(vcpu, val));
	}

	if (vmcb_read_from(vcpu, vmcb, ident, val) == 0) {
		return (0);
	}

	reg = swctx_regptr(svm_get_guest_regctx(vcpu), ident);

	if (reg != NULL) {
		*val = *reg;
		return (0);
	}

	SVM_CTR1(vcpu, "svm_getreg: unknown register %#x", ident);
	return (EINVAL);
}

/* Translate an L2 physical operand for software instruction emulation. */
static int
svm_translate_gpa(void *vcpui, uint64_t gpa, uint64_t gla __unused, int prot,
    bool usermode, bool guest_page_table,
    bool guest_page_writable __unused,
    bool guest_page_execute_disable __unused, bool check_only,
    uint64_t *translated)
{
	struct svm_nested_npt_result result;
	struct svm_vcpu *vcpu;
	uint64_t info1;
	uint8_t access;
	int error, retry;

	vcpu = vcpui;
	if (vcpu == NULL || translated == NULL || prot == 0 ||
	    (prot & ~VM_PROT_ALL) != 0 ||
	    (prot & (VM_PROT_WRITE | VM_PROT_EXECUTE)) ==
	    (VM_PROT_WRITE | VM_PROT_EXECUTE))
		return (EINVAL);
	if (!vcpu->nested_active ||
	    !vcpu->nested_vmcb12->ctrl.np_enable) {
		*translated = gpa;
		return (0);
	}
	if (vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	/* ROGPT is disabled: AMD checks L2 page-table walks as user writes. */
	error = svm_nested_npt_software_access(guest_page_table, usermode,
	    (prot & VM_PROT_WRITE) != 0,
	    (prot & VM_PROT_EXECUTE) != 0, &access, &info1);
	if (error != 0)
		return (error);
	for (retry = 0; retry < 8; retry++) {
		error = svm_nested_npt_root_translate(vcpu->nested_npt02,
		    vcpu->vcpu, vcpu->nested_npt12_root_gpa, gpa,
		    access, svm_nested_physical_width(
		    vm_mtrr_maxphyaddr(cpu_maxphyaddr)),
		    (amd_feature & AMDID_PAGE1GB) != 0, !check_only,
		    &result);
		if (error != EAGAIN)
			break;
	}
	if (error != 0)
		return (error);
	if (result.outcome != SVM_NESTED_NPT_TRANSLATED) {
		if (check_only)
			return (EFAULT);
		error = svm_nested_npt_reflect_info1(&result, info1,
		    &info1);
		if (error != 0)
			return (error);
		vcpu->nested_vmcb02->ctrl.exitcode = VMCB_EXIT_NPF;
		vcpu->nested_vmcb02->ctrl.exitinfo1 = info1;
		vcpu->nested_vmcb02->ctrl.exitinfo2 = gpa;
		vcpu->nested_vmcb02->ctrl.exitintinfo = 0;
		error = svm_nested_l2_reflect(vcpu);
		if (error != 0) {
			vcpu->nested_poisoned = true;
			return (error);
		}
		return (VMM_TRANSLATE_NESTED_EXIT);
	}
	*translated = result.l1_gpa;
	return (0);
}

static int
svm_setreg(void *vcpui, int ident, uint64_t val)
{
	struct svm_vcpu *vcpu;
	struct vmcb *vmcb;
	register_t *reg;

	vcpu = vcpui;
	vmcb = vcpu->nested_active ? vcpu->nested_vmcb02 : vcpu->vmcb;

	if (ident == VM_REG_GUEST_INTR_SHADOW) {
		if (vcpu->nested_active) {
			vmcb->ctrl.intr_shadow = val != 0;
			return (0);
		}
		return (svm_modify_intr_shadow(vcpu, val));
	}

	/* Do not permit user write access to VMCB fields by offset. */
	if (!VMCB_ACCESS_OK(ident)) {
		if (vmcb_write_to(vcpu, vmcb, ident, val) == 0) {
			if (vcpu->nested_active &&
			    ident == VM_REG_GUEST_RIP) {
				vcpu->nextrip = val;
				vm_set_nextrip(vcpu->vcpu, val);
			}
			return (0);
		}
	}

	reg = swctx_regptr(svm_get_guest_regctx(vcpu), ident);

	if (reg != NULL) {
		*reg = val;
		return (0);
	}

	if (ident == VM_REG_GUEST_ENTRY_INST_LENGTH) {
		/* Ignore. */
		return (0);
	}

	SVM_CTR1(vcpu, "svm_setreg: unknown register %#x", ident);
	return (EINVAL);
}

static int
svm_getdesc(void *vcpui, int reg, struct seg_desc *desc)
{
	struct svm_vcpu *vcpu;

	vcpu = vcpui;
	return (vmcb_getdesc_from(vcpu,
	    vcpu->nested_active ? vcpu->nested_vmcb02 : vcpu->vmcb,
	    reg, desc));
}

static int
svm_setdesc(void *vcpui, int reg, struct seg_desc *desc)
{
	struct svm_vcpu *vcpu;

	vcpu = vcpui;
	return (vmcb_setdesc_to(vcpu,
	    vcpu->nested_active ? vcpu->nested_vmcb02 : vcpu->vmcb,
	    reg, desc));
}

#ifdef BHYVE_SNAPSHOT
static int
svm_snapshot_reg(void *vcpui, int ident, struct vm_snapshot_meta *meta)
{
	struct svm_vcpu *vcpu;
	int ret;
	uint64_t val;

	vcpu = vcpui;
	if (meta->op == VM_SNAPSHOT_SAVE) {
		/* The architecture record is VMCB01, even while L2 is running. */
		if (ident == VM_REG_GUEST_INTR_SHADOW) {
			val = vcpu->vmcb->ctrl.intr_shadow;
			ret = 0;
		} else
			ret = vmcb_read_from(vcpu, vcpu->vmcb, ident, &val);
		if (ret != 0)
			goto done;

		SNAPSHOT_VAR_OR_LEAVE(val, meta, ret, done);
	} else if (meta->op == VM_SNAPSHOT_RESTORE) {
		SNAPSHOT_VAR_OR_LEAVE(val, meta, ret, done);
		if (ident == VM_REG_GUEST_INTR_SHADOW) {
			vcpu->vmcb->ctrl.intr_shadow = val != 0;
			ret = 0;
		} else
			ret = vmcb_write_to(vcpu, vcpu->vmcb, ident, val);
		if (ret != 0)
			goto done;
	} else {
		ret = EINVAL;
		goto done;
	}

done:
	return (ret);
}
#endif

static int
svm_setcap(void *vcpui, int type, int val)
{
	struct svm_vcpu *vcpu;
	struct vlapic *vlapic;
	int error;

	vcpu = vcpui;
	error = 0;

	switch (type) {
	case VM_CAP_HALT_EXIT:
		svm_setcap_intercept(vcpu, VMCB_CTRL1_INTCPT,
		    VMCB_INTCPT_HLT, val);
		break;
	case VM_CAP_PAUSE_EXIT:
		svm_setcap_intercept(vcpu, VMCB_CTRL1_INTCPT,
		    VMCB_INTCPT_PAUSE, val);
		break;
	case VM_CAP_UNRESTRICTED_GUEST:
		/* Unrestricted guest execution cannot be disabled in SVM */
		if (val == 0)
			error = EINVAL;
		break;
	case VM_CAP_BPT_EXIT:
		svm_setcap_intercept(vcpu, VMCB_EXC_INTCPT,
		    BIT(IDT_BP), val);
		break;
	case VM_CAP_IPI_EXIT:
		vlapic = vm_lapic(vcpu->vcpu);
		vlapic->ipi_exit = val;
		break;
	case VM_CAP_MASK_HWINTR:
		vcpu->caps &= ~(1 << VM_CAP_MASK_HWINTR);
		vcpu->caps |= (val << VM_CAP_MASK_HWINTR);
		break;
	case VM_CAP_NESTED_SVM:
		if (val != 0 && val != 1) {
			error = EINVAL;
			break;
		}
		if (val == 1 && nested_svm_allowed != 1) {
			error = EOPNOTSUPP;
			break;
		}
		/* CR8 emulation needs the decoded MOV CRx GPR operand. */
		if (val != 0 && !decode_assist()) {
			error = ENOTSUP;
			break;
		}
		if (val == 0) {
			/* A blocked L2 NMI must survive until its VMCB resumes. */
			for (size_t i = 0; i < nitems(vcpu->nested_vnmi_gpas);
			    i++) {
				if (vcpu->nested_vnmi_gpas[i] != 0) {
					error = EBUSY;
					break;
				}
			}
			if (error != 0)
				break;
		}
		error = svm_nested_msr_exposure_set(&vcpu->nested_msr, val,
		    vcpu->nested_config_locked || vcpu->nested_active ||
		    vcpu->nested_poisoned ||
		    vcpu->nested_pending.kind != SVM_NESTED_INSTRUCTION_NONE);
		if (error == 0 && val == 0)
			vcpu->nested_gif = true;
		break;
	case VM_CAP_RFLAGS_TF: {
		uint64_t rflags;

		/* Fetch RFLAGS. */
		if (svm_getreg(vcpu, VM_REG_GUEST_RFLAGS, &rflags)) {
			error = (EINVAL);
			break;
		}
		if (val) {
			/* Save current TF bit. */
			vcpu->dbg.rflags_tf = rflags & PSL_T;
			/* Trace next instruction. */
			if (svm_setreg(vcpu, VM_REG_GUEST_RFLAGS,
				(rflags | PSL_T))) {
				error = (EINVAL);
				break;
			}
			vcpu->caps |= (1 << VM_CAP_RFLAGS_TF);
			vcpu->nested_debug_step_l2 = vcpu->nested_active;
		} else {
			/*
			 * Restore shadowed RFLAGS.TF only if vCPU was
			 * previously stepped
			 */
			if (vcpu->caps & (1 << VM_CAP_RFLAGS_TF)) {
				rflags &= ~PSL_T;
				rflags |= vcpu->dbg.rflags_tf;
				vcpu->dbg.rflags_tf = 0;

				if (svm_setreg(vcpu, VM_REG_GUEST_RFLAGS,
					rflags)) {
					error = (EINVAL);
					break;
				}
				vcpu->caps &= ~(1 << VM_CAP_RFLAGS_TF);
			}
			vcpu->nested_debug_step_l2 = false;
		}

		svm_set_intercept(vcpu, VMCB_EXC_INTCPT, BIT(IDT_DB), val);
		if (vcpu->nested_active) {
			uint32_t *l2_exceptions;

			/* A capability change while L2 is frozen must reach VMCB02. */
			l2_exceptions = &vcpu->nested_vmcb02->ctrl.intercept[
			    VMCB_EXC_INTCPT];
			*l2_exceptions &= ~BIT(IDT_DB);
			*l2_exceptions |= (vcpu->vmcb->ctrl.intercept[
			    VMCB_EXC_INTCPT] |
			    vcpu->nested_vmcb12->ctrl.intercept[
			    VMCB_EXC_INTCPT]) & BIT(IDT_DB);
		}
		svm_set_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_POPF,
		    val);
		svm_set_intercept(vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_PUSHF,
		    val);
		if (vcpu->nested_active) {
			uint32_t *l2_ctrl1;
			uint32_t debug_flags;

			debug_flags = VMCB_INTCPT_POPF | VMCB_INTCPT_PUSHF;
			l2_ctrl1 = &vcpu->nested_vmcb02->ctrl.intercept[
			    VMCB_CTRL1_INTCPT];
			*l2_ctrl1 &= ~debug_flags;
			*l2_ctrl1 |= (vcpu->vmcb->ctrl.intercept[
			    VMCB_CTRL1_INTCPT] |
			    vcpu->nested_vmcb12->ctrl.intercept[
			    VMCB_CTRL1_INTCPT]) & debug_flags;
		}
		break;
	}
	default:
		error = ENOENT;
		break;
	}
	return (error);
}

static int
svm_getcap(void *vcpui, int type, int *retval)
{
	struct svm_vcpu *vcpu;
	struct vlapic *vlapic;
	int error;

	vcpu = vcpui;
	error = 0;

	switch (type) {
	case VM_CAP_HALT_EXIT:
		*retval = svm_get_intercept(vcpu, VMCB_CTRL1_INTCPT,
		    VMCB_INTCPT_HLT);
		break;
	case VM_CAP_PAUSE_EXIT:
		*retval = svm_get_intercept(vcpu, VMCB_CTRL1_INTCPT,
		    VMCB_INTCPT_PAUSE);
		break;
	case VM_CAP_UNRESTRICTED_GUEST:
		*retval = 1;	/* unrestricted guest is always enabled */
		break;
	case VM_CAP_BPT_EXIT:
		*retval = svm_get_intercept(vcpu, VMCB_EXC_INTCPT, BIT(IDT_BP));
		break;
	case VM_CAP_IPI_EXIT:
		vlapic = vm_lapic(vcpu->vcpu);
		*retval = vlapic->ipi_exit;
		break;
	case VM_CAP_RFLAGS_TF:
		*retval = !!(vcpu->caps & (1 << VM_CAP_RFLAGS_TF));
		break;
	case VM_CAP_MASK_HWINTR:
		*retval = !!(vcpu->caps & (1 << VM_CAP_MASK_HWINTR));
		break;
	case VM_CAP_NESTED_SVM:
		if (nested_svm_allowed != 1 || !decode_assist())
			error = ENOENT;
		else
			*retval = vcpu->nested_msr.exposed ? 1 : 0;
		break;
	default:
		error = ENOENT;
		break;
	}
	return (error);
}

static struct vmspace *
svm_vmspace_alloc(vm_offset_t min, vm_offset_t max)
{
	return (svm_npt_alloc(min, max));
}

static void
svm_vmspace_free(struct vmspace *vmspace)
{
	svm_npt_free(vmspace);
}

static struct vlapic *
svm_vlapic_init(void *vcpui)
{
	struct svm_vcpu *vcpu;
	struct vlapic *vlapic;

	vcpu = vcpui;
	vlapic = malloc(sizeof(struct vlapic), M_SVM_VLAPIC, M_WAITOK | M_ZERO);
	vlapic->vm = vcpu->sc->vm;
	vlapic->vcpu = vcpu->vcpu;
	vlapic->vcpuid = vcpu->vcpuid;
	vlapic->apic_page = malloc_aligned(PAGE_SIZE, PAGE_SIZE, M_SVM_VLAPIC,
	    M_WAITOK | M_ZERO);

	vlapic_init(vlapic);

	return (vlapic);
}

static void
svm_vlapic_cleanup(struct vlapic *vlapic)
{

        vlapic_cleanup(vlapic);
	free(vlapic->apic_page, M_SVM_VLAPIC);
        free(vlapic, M_SVM_VLAPIC);
}

#ifdef BHYVE_SNAPSHOT
static int
svm_vm_snapshot(void *vmi, struct vm_snapshot_meta *meta)
{
	struct svm_snapshot_restore *stage;
	struct svm_softc *sc;
	struct vcpu *generic_vcpu;
	uint8_t header[SVM_SNAPSHOT_VM_HEADER_SIZE];
	uint8_t magic[sizeof(SVM_SNAPSHOT_VM_MAGIC) - 1];
	uint16_t i;
	int error;

	if (vmi == NULL || meta == NULL)
		return (EINVAL);
	sc = vmi;
	/* Keep every vCPU's guest SVM policy stable through the checkpoint. */
	for (i = 0; i < vm_get_maxcpus(sc->vm); i++) {
		generic_vcpu = vm_vcpu(sc->vm, i);
		if (generic_vcpu == NULL)
			continue;
		if (vcpu_get_state(generic_vcpu, NULL) != VCPU_FROZEN)
			return (EBUSY);
		if (generic_vcpu->cookie == NULL)
			return (EPROTO);
		((struct svm_vcpu *)generic_vcpu->cookie)->nested_config_locked =
		    true;
	}
	if (meta->op == VM_SNAPSHOT_SAVE) {
		bcopy(SVM_SNAPSHOT_VM_MAGIC, header, sizeof(magic));
		le32enc(header + sizeof(magic), SVM_SNAPSHOT_VERSION);
		return (vm_snapshot_buf(header, sizeof(header), meta));
	}
	if (meta->op != VM_SNAPSHOT_RESTORE)
		return (EINVAL);
	if (sc->snapshot_restore != NULL)
		return (EBUSY);
	/* A legacy AMD image begins with CR0, never this eight-byte magic. */
	if (meta->buffer.buf_rem >= sizeof(magic)) {
		error = copyin(meta->buffer.buf, magic, sizeof(magic));
		if (error != 0)
			return (error);
	} else
		bzero(magic, sizeof(magic));
	if (bcmp(magic, SVM_SNAPSHOT_VM_MAGIC, sizeof(magic)) == 0) {
		error = vm_snapshot_buf(header, sizeof(header), meta);
		if (error != 0)
			return (error);
		if (le32dec(header + sizeof(magic)) < 1 ||
		    le32dec(header + sizeof(magic)) > SVM_SNAPSHOT_VERSION)
			return (EPROTONOSUPPORT);
	}
	stage = malloc(sizeof(*stage), M_SVM, M_NOWAIT | M_ZERO);
	if (stage == NULL)
		return (ENOMEM);
	stage->maxcpus = vm_get_maxcpus(sc->vm);
	stage->vcpus = mallocarray(stage->maxcpus, sizeof(*stage->vcpus),
	    M_SVM, M_NOWAIT | M_ZERO);
	if (stage->vcpus == NULL) {
		svm_snapshot_restore_free(stage);
		return (ENOMEM);
	}
	stage->legacy = bcmp(magic, SVM_SNAPSHOT_VM_MAGIC,
	    sizeof(magic)) != 0;
	stage->version = stage->legacy ? 0 :
	    le32dec(header + sizeof(magic));
	sc->snapshot_restore = stage;
	return (0);
}

static int
svm_vm_snapshot_complete(void *vmi, struct vm_snapshot_meta *meta, int status)
{
	struct svm_snapshot_restore *stage;
	struct svm_snapshot_vcpu_stage *vcpu_stage;
	struct svm_nested_npt_root *old_root;
	struct svm_softc *sc;
	struct vcpu *generic_vcpu;
	uint32_t active_count __unused;
	uint16_t i;

	if (vmi == NULL || meta == NULL)
		return (EINVAL);
	if (meta->op != VM_SNAPSHOT_RESTORE)
		return (0);
	sc = vmi;
	stage = sc->snapshot_restore;
	sc->snapshot_restore = NULL;
	if (status != 0) {
		SDT_PROBE5(vmm, svm, nested, restore, sc, status,
		    (stage != NULL ? stage->version : 0), 0, 0);
		svm_snapshot_restore_free(stage);
		return (0);
	}
	if (stage == NULL) {
		SDT_PROBE5(vmm, svm, nested, restore, sc, EPROTO, 0, 0, 0);
		return (EPROTO);
	}

	/* Complete all topology and frozen-state checks before first publication. */
	active_count = 0;
	for (i = 0; i < stage->maxcpus; i++) {
		generic_vcpu = vm_vcpu(sc->vm, i);
		vcpu_stage = &stage->vcpus[i];
		if (generic_vcpu == NULL) {
			if (vcpu_stage->valid) {
				SDT_PROBE5(vmm, svm, nested, restore, sc,
				    EPROTO, stage->version, active_count, i);
				svm_snapshot_restore_free(stage);
				return (EPROTO);
			}
			continue;
		}
		if (!vcpu_stage->valid || vcpu_stage->vcpu == NULL ||
		    vcpu_stage->vcpu->sc != sc ||
		    vcpu_stage->vcpu->vcpu != generic_vcpu ||
		    vcpu_stage->vcpu->vcpuid != i ||
		    (vcpu_stage->nested_active &&
		    (vcpu_stage->nested_vmcb12 == NULL ||
		    vcpu_stage->nested_vmcb02 == NULL ||
		    vcpu_stage->nested_npt02 == NULL)) ||
		    vcpu_get_state(generic_vcpu, NULL) != VCPU_FROZEN) {
			SDT_PROBE5(vmm, svm, nested, restore, sc, EPROTO,
			    stage->version, active_count, i);
			svm_snapshot_restore_free(stage);
			return (EPROTO);
		}
		if (vcpu_stage->nested_active)
			active_count++;
	}

	/*
	 * Every remaining publication is a bounded, non-failing write to a frozen
	 * vCPU.  There are no allocations or fallible setters here, so a late
	 * per-vCPU failure cannot expose a partially restored VM.
	 */
	for (i = 0; i < stage->maxcpus; i++) {
		vcpu_stage = &stage->vcpus[i];
		if (!vcpu_stage->valid)
			continue;
		bcopy(vcpu_stage->vcpu->snapshot_vmcb,
		    vcpu_stage->vcpu->vmcb, sizeof(*vcpu_stage->vcpu->vmcb));
		vcpu_stage->vcpu->swctx = vcpu_stage->swctx;
		vcpu_stage->vcpu->nextrip = vcpu_stage->nextrip;
		vm_set_nextrip(vcpu_stage->vcpu->vcpu,
		    vcpu_stage->nextrip);
		vcpu_stage->vcpu->mtrr = vcpu_stage->mtrr;
		vcpu_stage->vcpu->nested_msr = vcpu_stage->nested_msr;
		if (vcpu_stage->nested_active) {
			bcopy(vcpu_stage->nested_vmcb12,
			    vcpu_stage->vcpu->nested_vmcb12,
			    sizeof(*vcpu_stage->nested_vmcb12));
			bcopy(vcpu_stage->nested_vmcb02,
			    vcpu_stage->vcpu->nested_vmcb02,
			    sizeof(*vcpu_stage->nested_vmcb02));
		} else {
			bzero(vcpu_stage->vcpu->nested_vmcb12,
			    sizeof(*vcpu_stage->vcpu->nested_vmcb12));
			bzero(vcpu_stage->vcpu->nested_vmcb02,
			    sizeof(*vcpu_stage->vcpu->nested_vmcb02));
		}
		/* Transfer the fresh root; free the destination's old root later. */
		old_root = vcpu_stage->vcpu->nested_npt02;
		vcpu_stage->vcpu->nested_npt02 = vcpu_stage->nested_npt02;
		vcpu_stage->nested_npt02 = old_root;
		vcpu_stage->vcpu->nested_vmcb12_gpa =
		    vcpu_stage->nested_vmcb12_gpa;
		vcpu_stage->vcpu->nested_npt12_root_gpa =
		    vcpu_stage->nested_npt12_root_gpa;
		vcpu_stage->vcpu->nested_l1_next_rip =
		    vcpu_stage->nested_l1_next_rip;
		bcopy(vcpu_stage->nested_vnmi_gpas,
		    vcpu_stage->vcpu->nested_vnmi_gpas,
		    sizeof(vcpu_stage->nested_vnmi_gpas));
		vcpu_stage->vcpu->nested_active = vcpu_stage->nested_active;
		vcpu_stage->vcpu->nested_gif = vcpu_stage->nested_gif;
		if (vcpu_stage->nested_active)
			vcpu_stage->vcpu->nested_vmcb02->ctrl.tsc_offset =
			    vcpu_stage->vcpu->vmcb->ctrl.tsc_offset +
			    vcpu_stage->vcpu->nested_vmcb12->ctrl.tsc_offset;
		vcpu_stage->vcpu->nested_poisoned = false;
		vcpu_stage->vcpu->nested_pending.kind =
		    SVM_NESTED_INSTRUCTION_NONE;
		/* Destination CPU residency and translation caches start empty. */
		vcpu_stage->vcpu->lastcpu = NOCPU;
		vcpu_stage->vcpu->eptgen = 0;
		vcpu_stage->vcpu->asid.gen = 0;
		vcpu_stage->vcpu->nested_asid.gen = 0;
		vcpu_stage->vcpu->nested_eptgen = 0;
		vcpu_stage->vcpu->nested_asid.num = 0;
		vcpu_stage->vcpu->asid.num = 0;
		vcpu_stage->vcpu->vmcb->ctrl.asid = 0;
		vcpu_stage->vcpu->vmcb->ctrl.tlb_ctrl =
		    VMCB_TLB_FLUSH_NOTHING;
		vcpu_stage->vcpu->vmcb->ctrl.vmcb_clean = VMCB_CACHE_NONE;
		svm_set_dirty(vcpu_stage->vcpu, 0xffffffff);
	}
	SDT_PROBE5(vmm, svm, nested, restore, sc, 0, stage->version,
	    active_count, -1);
	svm_snapshot_restore_free(stage);
	return (0);
}

static int
svm_snapshot_nested_vnmi_validate(const uint64_t slots[SVM_NESTED_VNMI_SLOTS],
    bool exposed)
{
	uint64_t encoded, gpa, previous;
	uint8_t width;
	int i, j;

	width = svm_nested_physical_width(vm_mtrr_maxphyaddr(cpu_maxphyaddr));
	for (i = 0; i < SVM_NESTED_VNMI_SLOTS; i++) {
		encoded = slots[i];
		if (encoded == 0)
			continue;
		gpa = encoded & ~(SVM_NESTED_VNMI_VALID |
		    SVM_NESTED_VNMI_BLOCKED);
		if (!exposed || (svm_feature & AMD_CPUID_SVM_VNMI) == 0 ||
		    (encoded & SVM_NESTED_VNMI_VALID) == 0 ||
		    (gpa & PAGE_MASK) != 0 ||
		    gpa > (1ULL << width) - PAGE_SIZE)
			return (EPROTO);
		for (j = 0; j < i; j++) {
			previous = slots[j] & ~(SVM_NESTED_VNMI_VALID |
			    SVM_NESTED_VNMI_BLOCKED);
			if (slots[j] != 0 && previous == gpa)
				return (EPROTO);
		}
	}
	return (0);
}

static int
svm_snapshot_nested_save(struct svm_vcpu *vcpu,
    struct vm_snapshot_meta *meta)
{
	struct svm_nested_vmcb12_view view;
	struct vmcb *portable;
	uint8_t header[SVM_SNAPSHOT_VCPU_HEADER_SIZE];
	uint8_t vnmi_image[SVM_NESTED_VNMI_SLOTS * sizeof(uint64_t)];
	uint32_t flags;
	int error, i;

	if (vcpu->nested_poisoned ||
	    vcpu->nested_pending.kind != SVM_NESTED_INSTRUCTION_NONE)
		return (EBUSY);
	if (!svm_nested_msr_state_valid(&vcpu->nested_msr,
	    svm_nested_physical_width(vm_mtrr_maxphyaddr(cpu_maxphyaddr))))
		return (EPROTO);
	if (!vcpu->nested_msr.exposed && !vcpu->nested_gif)
		return (EPROTO);
	portable = NULL;
	if (vcpu->nested_active) {
		if (vcpu->nested_gif || !vcpu->nested_msr.exposed ||
		    !vcpu->nested_msr.svme ||
		    vcpu->nested_npt02 == NULL ||
		    vcpu->nested_vmcb12 == NULL ||
		    vcpu->nested_vmcb02 == NULL ||
		    vcpu->nested_vmcb02->ctrl.np_enable != 1 ||
		    vcpu->nested_vmcb02->ctrl.n_cr3 !=
		    svm_nested_npt_root_pa(vcpu->nested_npt02) ||
		    vcpu->nested_vmcb02->ctrl.iopm_base_pa !=
		    vtophys(vcpu->sc->iopm_bitmap) ||
		    vcpu->nested_vmcb02->ctrl.msrpm_base_pa !=
		    vtophys(vcpu->sc->nested_msr_bitmap) ||
		    vcpu->nextrip != vcpu->nested_vmcb02->state.rip ||
		    vcpu->nested_l1_next_rip <= vcpu->vmcb->state.rip ||
		    vcpu->nested_l1_next_rip - vcpu->vmcb->state.rip >
		    VIE_INST_SIZE)
			return (EPROTO);
		svm_nested_vnmi_sync(vcpu);
		if (vcpu->nested_vmcb02->ctrl.v_nmi_blocking &&
		    svm_nested_vnmi_slot(vcpu->nested_vnmi_gpas,
		    vcpu->nested_vmcb12_gpa, false) == NULL)
			return (EPROTO);
		portable = malloc(sizeof(*portable), M_SVM, M_NOWAIT | M_ZERO);
		if (portable == NULL)
			return (ENOMEM);
		svm_nested_vmcb_checkpoint_copy(portable, vcpu->nested_vmcb12,
		    vcpu->nested_vmcb02,
		    vcpu->nested_vmcb12->ctrl.lbr_virt_en != 0,
		    vcpu->nested_vmcb12->ctrl.np_enable != 0);
		if (!svm_nested_vmcb12_view_from_vmcb(&view, portable,
		    vcpu->nested_vmcb12_gpa, vcpu->nested_msr.hsave_gpa) ||
		    !svm_nested_vmcb12_view_valid(&view,
		    svm_nested_physical_width(vm_mtrr_maxphyaddr(
		    cpu_maxphyaddr)), true) ||
		    view.npt_root_gpa != vcpu->nested_npt12_root_gpa) {
			error = EPROTO;
			goto out;
		}
	}
	error = svm_snapshot_nested_vnmi_validate(vcpu->nested_vnmi_gpas,
	    vcpu->nested_msr.exposed);
	if (error != 0)
		goto out;
	bzero(header, sizeof(header));
	flags = (vcpu->nested_msr.exposed ? SVM_SNAPSHOT_F_EXPOSED : 0) |
	    (vcpu->nested_msr.svme ? SVM_SNAPSHOT_F_SVME : 0) |
	    (vcpu->nested_active ? SVM_SNAPSHOT_F_ACTIVE : 0) |
	    (!vcpu->nested_gif ? SVM_SNAPSHOT_F_GIF_CLEAR : 0);
	le32enc(header, flags);
	le64enc(header + 8, vcpu->nested_msr.hsave_gpa);
	le64enc(header + 16, vcpu->nested_msr.vm_cr);
	if (vcpu->nested_active) {
		le64enc(header + 24, vcpu->nested_vmcb12_gpa);
		le64enc(header + 32, vcpu->nested_l1_next_rip);
		le64enc(header + 40, vcpu->nested_npt12_root_gpa);
	}
	error = vm_snapshot_buf(header, sizeof(header), meta);
	if (error == 0 && portable != NULL)
		error = vm_snapshot_buf(portable, sizeof(*portable), meta);
	if (error == 0) {
		for (i = 0; i < SVM_NESTED_VNMI_SLOTS; i++)
			le64enc(vnmi_image + i * sizeof(uint64_t),
			    vcpu->nested_vnmi_gpas[i]);
		error = vm_snapshot_buf(vnmi_image, sizeof(vnmi_image), meta);
	}
out:
	if (portable != NULL) {
		explicit_bzero(portable, sizeof(*portable));
		free(portable, M_SVM);
	}
	return (error);
}

static int
svm_snapshot_nested_vnmi_restore(struct svm_snapshot_vcpu_stage *stage,
    uint32_t version, struct vm_snapshot_meta *meta)
{
	uint8_t image[SVM_NESTED_VNMI_SLOTS * sizeof(uint64_t)];
	int error, i;

	if (version < 2)
		return (0);
	error = vm_snapshot_buf(image, sizeof(image), meta);
	if (error != 0)
		return (error);
	for (i = 0; i < SVM_NESTED_VNMI_SLOTS; i++)
		stage->nested_vnmi_gpas[i] =
		    le64dec(image + i * sizeof(uint64_t));
	return (svm_snapshot_nested_vnmi_validate(
	    stage->nested_vnmi_gpas, stage->nested_msr.exposed));
}

static int
svm_snapshot_nested_restore(struct svm_vcpu *vcpu,
    struct svm_snapshot_vcpu_stage *stage, bool legacy, uint32_t version,
    struct vm_snapshot_meta *meta)
{
	struct svm_nested_vmcb12_view view;
	struct svm_nested_msr_state *msr;
	uint8_t header[SVM_SNAPSHOT_VCPU_HEADER_SIZE];
	uint32_t flags;
	int error;

	if (legacy) {
		if (vcpu->nested_msr.exposed)
			return (EOPNOTSUPP);
		stage->nested_msr = vcpu->nested_msr;
		stage->nested_gif = true;
		return (0);
	}
	error = vm_snapshot_buf(header, sizeof(header), meta);
	if (error != 0)
		return (error);
	flags = le32dec(header);
	if ((flags & ~(SVM_SNAPSHOT_F_EXPOSED | SVM_SNAPSHOT_F_SVME |
	    SVM_SNAPSHOT_F_ACTIVE | SVM_SNAPSHOT_F_GIF_CLEAR)) != 0 ||
	    le32dec(header + 4) != 0)
		return (EPROTO);
	stage->nested_gif = (flags & SVM_SNAPSHOT_F_GIF_CLEAR) == 0;
	msr = &stage->nested_msr;
	svm_nested_msr_state_init(msr);
	msr->exposed = (flags & SVM_SNAPSHOT_F_EXPOSED) != 0;
	msr->svme = (flags & SVM_SNAPSHOT_F_SVME) != 0;
	msr->hsave_gpa = le64dec(header + 8);
	msr->vm_cr = le64dec(header + 16);
	if (msr->exposed != vcpu->nested_msr.exposed)
		return (EOPNOTSUPP);
	if (!msr->exposed && !stage->nested_gif)
		return (EPROTO);
	if (!svm_nested_msr_state_valid(msr,
	    svm_nested_physical_width(vm_mtrr_maxphyaddr(cpu_maxphyaddr))))
		return (EPROTO);
	stage->nested_active = (flags & SVM_SNAPSHOT_F_ACTIVE) != 0;
	if (stage->nested_active && stage->nested_gif)
		return (EPROTO);
	stage->nested_vmcb12_gpa = le64dec(header + 24);
	stage->nested_l1_next_rip = le64dec(header + 32);
	stage->nested_npt12_root_gpa = le64dec(header + 40);
	if (!stage->nested_active) {
		if ((stage->nested_vmcb12_gpa |
		    stage->nested_l1_next_rip |
		    stage->nested_npt12_root_gpa) != 0)
			return (EPROTO);
		return (svm_snapshot_nested_vnmi_restore(stage, version,
		    meta));
	}
	if (!msr->exposed || !msr->svme)
		return (EPROTO);
	stage->nested_vmcb12 = malloc(sizeof(*stage->nested_vmcb12),
	    M_SVM, M_NOWAIT | M_ZERO);
	if (stage->nested_vmcb12 == NULL)
		return (ENOMEM);
	error = vm_snapshot_buf(stage->nested_vmcb12,
	    sizeof(*stage->nested_vmcb12), meta);
	if (error != 0)
		return (error);
	if (!svm_nested_vmcb12_view_from_vmcb(&view, stage->nested_vmcb12,
	    stage->nested_vmcb12_gpa, msr->hsave_gpa) ||
	    !svm_nested_vmcb12_view_valid(&view,
	    svm_nested_physical_width(vm_mtrr_maxphyaddr(cpu_maxphyaddr)),
	    true) || view.npt_root_gpa != stage->nested_npt12_root_gpa)
		return (EPROTO);
	return (svm_snapshot_nested_vnmi_restore(stage, version, meta));
}

static int
svm_vcpu_snapshot_apply(struct svm_vcpu *vcpu,
    struct vm_snapshot_meta *meta)
{
	int err, running, hostcpu;

/*
 * Keep decoding and application in lockstep.  A failed field must stop this
 * ordered VMCB record immediately; continuing used to consume and potentially
 * apply later fields after an earlier error.  Full candidate-state staging is
 * deliberately handled by the architecture-record restore phase.
 */
#define	SVM_SNAPSHOT_CALL_OR_LEAVE(CALL) do { \
	err = (CALL); \
	if (err != 0) \
		goto done; \
} while (0)

	/*
	 * The common snapshot session freezes every vCPU before invoking the
	 * architecture callback.  Keep that boundary explicit here as well:
	 * the VMCB and its derived residency fields are not a coherent image
	 * while the vCPU is runnable, even if it happens to be running locally.
	 */
	if (vcpu == NULL || meta == NULL)
		return (EINVAL);
	if (vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	if (vcpu->nested_pending.kind != SVM_NESTED_INSTRUCTION_NONE)
		return (EBUSY);
	if (!svm_nested_msr_state_valid(&vcpu->nested_msr,
	    svm_nested_physical_width(vm_mtrr_maxphyaddr(cpu_maxphyaddr))))
		return (EPROTO);
	if (meta->op == VM_SNAPSHOT_SAVE && !vm_mtrr_validate(&vcpu->mtrr,
	    vm_mtrr_maxphyaddr(cpu_maxphyaddr)))
		return (EINVAL);
	err = 0;

	running = vcpu_is_running(vcpu->vcpu, &hostcpu);
	if (running && hostcpu != curcpu) {
		printf("%s: %s%d is running", __func__, vm_name(vcpu->sc->vm),
		    vcpu->vcpuid);
		return (EINVAL);
	}

	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_CR0, meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_CR2, meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_CR3, meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_CR4, meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_DR6, meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_DR7, meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_RAX, meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_RSP, meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_RIP, meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_RFLAGS, meta));

	/* Guest segments */
	/* ES */
	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_ES, meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_desc(vcpu,
	    VM_REG_GUEST_ES, meta));

	/* CS */
	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_CS, meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_desc(vcpu,
	    VM_REG_GUEST_CS, meta));

	/* SS */
	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_SS, meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_desc(vcpu,
	    VM_REG_GUEST_SS, meta));

	/* DS */
	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_DS, meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_desc(vcpu,
	    VM_REG_GUEST_DS, meta));

	/* FS */
	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_FS, meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_desc(vcpu,
	    VM_REG_GUEST_FS, meta));

	/* GS */
	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_GS, meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_desc(vcpu,
	    VM_REG_GUEST_GS, meta));

	/* TR */
	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_TR, meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_desc(vcpu,
	    VM_REG_GUEST_TR, meta));

	/* LDTR */
	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_LDTR, meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_desc(vcpu,
	    VM_REG_GUEST_LDTR, meta));

	/* EFER */
	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_EFER, meta));

	/* IDTR and GDTR */
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_desc(vcpu,
	    VM_REG_GUEST_IDTR, meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_desc(vcpu,
	    VM_REG_GUEST_GDTR, meta));

	/* Specific AMD registers */
	SVM_SNAPSHOT_CALL_OR_LEAVE(svm_snapshot_reg(vcpu,
	    VM_REG_GUEST_INTR_SHADOW, meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_CR_INTERCEPT, 4), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_DR_INTERCEPT, 4), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_EXC_INTERCEPT, 4), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_INST1_INTERCEPT, 4), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_INST2_INTERCEPT, 4), meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_PAUSE_FILTHRESH, 2), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_PAUSE_FILCNT, 2), meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_ASID, 4), meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_TLB_CTRL, 4), meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_VIRQ, 8), meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_EXIT_REASON, 8), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_EXITINFO1, 8), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_EXITINFO2, 8), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_EXITINTINFO, 8), meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_NP_ENABLE, 1), meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_AVIC_BAR, 8), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_AVIC_PAGE, 8), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_AVIC_LT, 8), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_AVIC_PT, 8), meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_CPL, 1), meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_STAR, 8), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_LSTAR, 8), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_CSTAR, 8), meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_SFMASK, 8), meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_KERNELGBASE, 8), meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_SYSENTER_CS, 8), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_SYSENTER_ESP, 8), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_SYSENTER_EIP, 8), meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_GUEST_PAT, 8), meta));

	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_DBGCTL, 8), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_BR_FROM, 8), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_BR_TO, 8), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_INT_FROM, 8), meta));
	SVM_SNAPSHOT_CALL_OR_LEAVE(vmcb_snapshot_any(vcpu,
	    VMCB_ACCESS(VMCB_OFF_INT_TO, 8), meta));

	/* Snapshot swctx for virtual cpu */
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_rbp, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_rbx, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_rcx, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_rdx, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_rdi, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_rsi, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_r8, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_r9, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_r10, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_r11, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_r12, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_r13, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_r14, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_r15, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_dr0, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_dr1, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_dr2, meta, err, done);
	SNAPSHOT_VAR_OR_LEAVE(vcpu->swctx.sctx_dr3, meta, err, done);

	/* Restore the remaining guest architectural field. */
	SNAPSHOT_VAR_OR_LEAVE(vcpu->nextrip, meta, err, done);

	SNAPSHOT_BUF_OR_LEAVE(&vcpu->mtrr, sizeof(vcpu->mtrr), meta, err, done);
	if (!vm_mtrr_validate(&vcpu->mtrr,
	    vm_mtrr_maxphyaddr(cpu_maxphyaddr)))
		err = EINVAL;

done:
#undef SVM_SNAPSHOT_CALL_OR_LEAVE
	return (err);
}

static int
svm_snapshot_vmcb_validate(const struct svm_vcpu *vcpu,
    const struct vmcb *candidate)
{
	const struct vmcb_ctrl *ctrl, *live;
	const struct vmcb_state *state;
	uint32_t required1, required2, required_cr;
	uint8_t physical_width;

	ctrl = &candidate->ctrl;
	state = &candidate->state;
	live = &vcpu->vmcb->ctrl;
	physical_width = vm_mtrr_maxphyaddr(cpu_maxphyaddr);
	if (vcpu->nested_msr.exposed)
		physical_width = svm_nested_physical_width(physical_width);
	required1 = VMCB_INTCPT_IO | VMCB_INTCPT_MSR |
	    VMCB_INTCPT_CPUID | VMCB_INTCPT_INTR | VMCB_INTCPT_INIT |
	    VMCB_INTCPT_NMI | VMCB_INTCPT_SMI | VMCB_INTCPT_SHUTDOWN |
	    VMCB_INTCPT_FERR_FREEZE | VMCB_INTCPT_INVD |
	    VMCB_INTCPT_INVLPGA;
	required2 = VMCB_INTCPT_VMRUN | VMCB_INTCPT_VMLOAD |
	    VMCB_INTCPT_VMSAVE | VMCB_INTCPT_STGI | VMCB_INTCPT_CLGI |
	    VMCB_INTCPT_SKINIT | VMCB_INTCPT_ICEBP |
	    VMCB_INTCPT_MONITOR | VMCB_INTCPT_MWAIT;
	required_cr = 0xffff & ~(BIT(0) | BIT(2) | BIT(3) | BIT(4) |
	    BIT(8));
	required_cr |= required_cr << 16;

	/*
	 * The architecture record contains raw intercept words.  A corrupt or
	 * incompatible checkpoint must not disable the exits which enforce the
	 * guest CPU model, or replace destination-owned NPT and bitmap roots.
	 * Validate before any staged VMCB is published.
	 */
	if ((ctrl->intercept[VMCB_CR_INTCPT] & required_cr) !=
	    required_cr ||
	    (ctrl->intercept[VMCB_EXC_INTCPT] & BIT(IDT_MC)) == 0 ||
	    (ctrl->intercept[VMCB_CTRL1_INTCPT] & required1) != required1 ||
	    (ctrl->intercept[VMCB_CTRL2_INTCPT] & required2) != required2 ||
	    ctrl->np_enable != 1 || ctrl->v_intr_masking != 1 ||
	    ((const uint8_t *)ctrl)[VMCB_OFF_NP_ENABLE] != 1 ||
	    ((const uint8_t *)ctrl)[VMCB_OFF_VIRQ + 3] != 1 ||
	    ctrl->pad2[0] != 0 || ctrl->pad2[1] != 0 ||
	    ctrl->pad2[2] != 0 ||
	    ctrl->n_cr3 != live->n_cr3 ||
	    ctrl->iopm_base_pa != live->iopm_base_pa ||
	    ctrl->msrpm_base_pa != live->msrpm_base_pa ||
	    (state->efer & EFER_SVM) == 0 ||
	    (state->efer & (EFER_MBZ_BITS | 0xfe)) != 0 ||
	    !svm_nested_guest_physical_range_valid(state->cr3, 1,
	    physical_width) ||
	    ((state->dr6 | state->dr7) & ~0xffffffffULL) != 0 ||
	    !svm_nested_l2_pat_valid(state->g_pat) ||
	    !svm_nested_state_mode_valid(state->efer, state->cr0,
	    state->cr4))
		return (EPROTO);
	return (0);
}

static int
svm_vcpu_snapshot(void *vcpui, struct vm_snapshot_meta *meta)
{
	struct svm_vcpu candidate, *vcpu;
	struct svm_snapshot_restore *stage;
	struct svm_snapshot_vcpu_stage *vcpu_stage;
	int error;

	if (vcpui == NULL || meta == NULL)
		return (EINVAL);
	vcpu = vcpui;
	if (vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	if (vcpu->startup_claim_phase != SVM_STARTUP_CLAIM_EMPTY)
		return (EBUSY);
	/*
	 * The architecture record does not carry the L0 debug single-step
	 * bookkeeping or the temporary hardware-interrupt mask.  Restoring
	 * either from the destination's existing vCPU would change the meaning
	 * of the saved intercepts and pending events.
	 */
	if ((vcpu->caps & ((1 << VM_CAP_RFLAGS_TF) |
	    (1 << VM_CAP_MASK_HWINTR))) != 0 ||
	    vcpu->nested_debug_step_l2 ||
	    vcpu->dbg.rflags_tf != 0 || vcpu->dbg.popf_sstep ||
	    vcpu->dbg.pushf_sstep)
		return (EBUSY);
	if (meta->op == VM_SNAPSHOT_SAVE) {
		error = svm_snapshot_vmcb_validate(vcpu, vcpu->vmcb);
		if (error != 0)
			return (error);
		error = svm_snapshot_nested_save(vcpu, meta);
		if (error != 0)
			return (error);
	}
	if (meta->op != VM_SNAPSHOT_RESTORE)
		return (svm_vcpu_snapshot_apply(vcpu, meta));
	stage = vcpu->sc->snapshot_restore;
	if (stage == NULL || vcpu->vcpuid < 0 ||
	    vcpu->vcpuid >= stage->maxcpus ||
	    vm_vcpu(vcpu->sc->vm, vcpu->vcpuid) != vcpu->vcpu)
		return (EPROTO);
	vcpu_stage = &stage->vcpus[vcpu->vcpuid];
	if (vcpu_stage->valid)
		return (EPROTO);
	error = svm_snapshot_nested_restore(vcpu, vcpu_stage,
	    stage->legacy, stage->version, meta);
	if (error != 0)
		return (error);

	/*
	 * The VMCB is software-owned memory while this vCPU is frozen.  Decode
	 * the complete fixed-order record into a private copy and make the live
	 * VMCB visible only after all record reads and architectural setters have
	 * succeeded.  This avoids relying on best-effort per-field rollback.
	 */
	if (vcpu->snapshot_vmcb == NULL)
		return (ENOMEM);
	candidate = *vcpu;
	bcopy(vcpu->vmcb, vcpu->snapshot_vmcb, sizeof(*vcpu->vmcb));
	candidate.vmcb = vcpu->snapshot_vmcb;
	candidate.nested_msr = vcpu_stage->nested_msr;
	error = svm_vcpu_snapshot_apply(&candidate, meta);
	if (error != 0)
		return (error);
	/*
	 * The architecture record carries physical SVME; the header carries
	 * L1's separate virtual SVME bit.  Validate each independently.
	 */
	if (!svm_nested_msr_state_valid(&candidate.nested_msr,
	    svm_nested_physical_width(vm_mtrr_maxphyaddr(cpu_maxphyaddr))))
		return (EPROTO);
	error = svm_snapshot_vmcb_validate(vcpu, candidate.vmcb);
	if (error != 0)
		return (error);
	if (vcpu_stage->nested_active) {
		if (candidate.nextrip !=
		    vcpu_stage->nested_vmcb12->state.rip ||
		    vcpu_stage->nested_l1_next_rip <=
		    candidate.vmcb->state.rip ||
		    vcpu_stage->nested_l1_next_rip -
		    candidate.vmcb->state.rip > VIE_INST_SIZE)
			return (EPROTO);
		error = svm_nested_npt_root_create(
		    VM_MAXUSER_ADDRESS_LA48, &vcpu_stage->nested_npt02);
		if (error != 0)
			return (error);
		vcpu_stage->nested_vmcb02 = malloc(
		    sizeof(*vcpu_stage->nested_vmcb02), M_SVM,
		    M_NOWAIT | M_ZERO);
		if (vcpu_stage->nested_vmcb02 == NULL)
			return (ENOMEM);
		error = svm_nested_vmcb02_compose(
		    vcpu_stage->nested_vmcb02, candidate.vmcb,
		    vcpu_stage->nested_vmcb12,
		    svm_nested_npt_root_pa(vcpu_stage->nested_npt02),
		    vtophys(vcpu->sc->iopm_bitmap),
		    vtophys(vcpu->sc->nested_msr_bitmap), 1);
		if (error != 0)
			return (error);
		error = svm_nested_vnmi_prepare(vcpu_stage->nested_vmcb02,
		    vcpu_stage->nested_vmcb12_gpa,
		    vcpu_stage->nested_vnmi_gpas);
		if (error != 0)
			return (error);
		svm_nested_vmcb_aux_copy(vcpu_stage->nested_vmcb02,
		    vcpu_stage->nested_vmcb12);
		bcopy((const uint8_t *)vcpu_stage->nested_vmcb12 +
		    VMCB_OFF_DBGCTL,
		    (uint8_t *)vcpu_stage->nested_vmcb02 + VMCB_OFF_DBGCTL,
		    0x28);
		vcpu_stage->nested_vmcb02->ctrl.asid = 0;
	}

	vcpu_stage->vcpu = vcpu;
	vcpu_stage->swctx = candidate.swctx;
	vcpu_stage->nextrip = candidate.nextrip;
	vcpu_stage->mtrr = candidate.mtrr;
	vcpu_stage->valid = true;
	return (0);
}

static int
svm_restore_tsc(void *vcpui, uint64_t offset)
{
	struct svm_vcpu *vcpu = vcpui;

	svm_set_tsc_offset(vcpu, offset);

	return (0);
}
#endif

static void
svm_nested_instruction_resume(struct svm_vcpu *vcpu, uint64_t rip)
{

	vcpu->nextrip = rip;
	vcpu->vmcb->state.rip = rip;
	vm_set_nextrip(vcpu->vcpu, rip);
}

static int
svm_nested_instruction_operand(struct svm_vcpu *vcpu,
    const struct svm_nested_instruction_pending *pending, uint64_t *gpa,
    bool *fault)
{
	struct vm_guest_paging paging;
	struct vie vie;
	uint64_t cs_base, length;
	uint8_t default_bits, opcode;
	int error, injected;

	if (pending == NULL || gpa == NULL || fault == NULL ||
	    pending->next_rip <= pending->rip)
		return (EPROTO);
	length = pending->next_rip - pending->rip;
	if (length < 3 || length > VIE_INST_SIZE)
		return (EPROTO);
	svm_paging_info(vcpu->vmcb, &paging);
	default_bits = paging.cpu_mode == CPU_MODE_64BIT ? 64 :
	    (vcpu->vmcb->state.cs.attrib & VMCB_CS_ATTRIB_D) != 0 ? 32 : 16;
	cs_base = paging.cpu_mode == CPU_MODE_64BIT ? 0 :
	    vcpu->vmcb->state.cs.base;
	if (pending->rip > UINT64_MAX - cs_base)
		return (EPROTO);
	opcode = pending->kind == SVM_NESTED_INSTRUCTION_VMRUN ? 0xd8 :
	    pending->kind == SVM_NESTED_INSTRUCTION_VMLOAD ? 0xda : 0xdb;
	vie_init(&vie, NULL, 0);
	injected = 0;
	error = vmm_fetch_instruction(vcpu->vcpu, &paging,
	    pending->rip + cs_base, length, &vie, &injected);
	if (error != 0)
		return (error);
	*fault = injected != 0;
	if (*fault)
		return (0);
	return (svm_nested_operand_gpa(vie.inst, length, default_bits,
	    opcode, pending->vmcb_gpa, gpa));
}

static int
svm_nested_l2_resume(struct svm_vcpu *vcpu)
{
	uint64_t eventinj;
	int error;

	error = svm_nested_l2_event_replay(
	    vcpu->nested_vmcb02->ctrl.eventinj,
	    vcpu->nested_vmcb02->ctrl.exitintinfo, &eventinj);
	if (error != 0)
		return (error);
	if ((vcpu->nested_vmcb02->ctrl.exitintinfo &
	    VMCB_EVENTINJ_VALID) != 0) {
		vcpu->nested_vmcb02->ctrl.eventinj = eventinj;
		vcpu->nested_vmcb02->ctrl.exitintinfo = 0;
	}
	vcpu->nextrip = vcpu->nested_vmcb02->state.rip;
	vm_set_nextrip(vcpu->vcpu, vcpu->nextrip);
	vcpu->nested_pending.kind = SVM_NESTED_INSTRUCTION_NONE;
	return (0);
}

static int
svm_nested_l2_reflect(struct svm_vcpu *vcpu)
{
	struct vmcb *vmcb02;
	uint64_t rflags_before;
	uint64_t vnmi_before[SVM_NESTED_VNMI_SLOTS];
	int error;

	vmcb02 = vcpu->nested_vmcb02;
	rflags_before = vmcb02->state.rflags;
	bcopy(vcpu->nested_vnmi_gpas, vnmi_before, sizeof(vnmi_before));
	svm_nested_vnmi_sync(vcpu);
	if (vcpu->nested_debug_step_l2) {
		/* The L0 step bit is not part of the L2 state written to VMCB12. */
		vmcb02->state.rflags &= ~PSL_T;
		vmcb02->state.rflags |= vcpu->dbg.rflags_tf;
	}
	error = svm_nested_vmcb12_exit_write(vcpu->vcpu,
	    vcpu->nested_vmcb12_gpa,
	    svm_nested_physical_width(vm_mtrr_maxphyaddr(cpu_maxphyaddr)),
	    vmcb02,
	    vcpu->nested_vmcb12->ctrl.lbr_virt_en != 0,
	    vcpu->nested_vmcb12->ctrl.np_enable != 0);
	if (error != 0) {
		vmcb02->state.rflags = rflags_before;
		bcopy(vnmi_before, vcpu->nested_vnmi_gpas,
		    sizeof(vnmi_before));
		return (error);
	}
	if (!vcpu->nested_vmcb12->ctrl.np_enable) {
		vcpu->vmcb->state.g_pat = vmcb02->state.g_pat;
		svm_set_dirty(vcpu, VMCB_CACHE_NP);
	}
	/* VMRUN does not bank the VMLOAD MSRs; L2 changes remain live in L1. */
	svm_nested_vmcb_aux_copy(vcpu->vmcb, vmcb02);
	if (!vcpu->nested_vmcb12->ctrl.lbr_virt_en)
		bcopy((const uint8_t *)vmcb02 + VMCB_OFF_DBGCTL,
		    (uint8_t *)vcpu->vmcb + VMCB_OFF_DBGCTL, 0x28);
	if (vcpu->nested_debug_step_l2) {
		/* Continue the requested step in L1 after L2 exits to it. */
		vcpu->dbg.rflags_tf = vcpu->vmcb->state.rflags & PSL_T;
		vcpu->vmcb->state.rflags |= PSL_T;
		vcpu->nested_debug_step_l2 = false;
	}
	/* VMRUN/#VMEXIT do not bank the non-RAX general registers. */
	vcpu->nested_active = false;
	vcpu->nested_gif = false;
	svm_nested_instruction_resume(vcpu, vcpu->nested_l1_next_rip);
	svm_set_dirty(vcpu, 0xffffffff);
	vcpu->nested_pending.kind = SVM_NESTED_INSTRUCTION_NONE;
	return (0);
}

static int
svm_nested_l2_shutdown(struct svm_vcpu *vcpu)
{
	uint64_t *vnmi_slot;
	int error;

	if ((vcpu->nested_vmcb12->ctrl.intercept[VMCB_CTRL1_INTCPT] &
	    VMCB_INTCPT_SHUTDOWN) == 0) {
		/* An unintercepted L2 shutdown triple faults the L1 VM. */
		(void)vm_suspend(vcpu->sc->vm, VM_SUSPEND_TRIPLEFAULT);
		vm_exit_suspended(vcpu->vcpu, vcpu->nested_l1_next_rip);
		vcpu->nested_pending.kind = SVM_NESTED_INSTRUCTION_NONE;
		vcpu->nested_poisoned = true;
		return (0);
	}
	/* The hardware VMCB saved state after SHUTDOWN is undefined. */
	error = svm_nested_vmcb12_shutdown_write(vcpu->vcpu,
	    vcpu->nested_vmcb12_gpa,
	    svm_nested_physical_width(vm_mtrr_maxphyaddr(cpu_maxphyaddr)));
	if (error != 0)
		return (error);
	vnmi_slot = svm_nested_vnmi_slot(vcpu->nested_vnmi_gpas,
	    vcpu->nested_vmcb12_gpa, false);
	if (vnmi_slot != NULL)
		*vnmi_slot = 0;
	if (vcpu->nested_debug_step_l2) {
		vcpu->dbg.rflags_tf = vcpu->vmcb->state.rflags & PSL_T;
		vcpu->vmcb->state.rflags |= PSL_T;
		vcpu->nested_debug_step_l2 = false;
	}
	vcpu->nested_active = false;
	vcpu->nested_gif = false;
	svm_nested_instruction_resume(vcpu, vcpu->nested_l1_next_rip);
	svm_set_dirty(vcpu, 0xffffffff);
	vcpu->nested_pending.kind = SVM_NESTED_INSTRUCTION_NONE;
	return (0);
}

static int
svm_nested_l2_synthetic_exception(struct svm_vcpu *vcpu, uint8_t vector,
    bool error_code_valid, uint32_t error_code)
{
	struct svm_nested_synthetic_exception prepared;
	struct vmcb_ctrl before;
	struct vmcb_ctrl *ctrl;
	int error;

	ctrl = &vcpu->nested_vmcb02->ctrl;
	error = svm_nested_synthetic_exception_prepare(
	    vcpu->nested_vmcb12->ctrl.intercept[VMCB_EXC_INTCPT],
	    ctrl->eventinj, ctrl->exitintinfo, vector, error_code_valid,
	    error_code, &prepared);
	if (error != 0)
		return (error);
	before = *ctrl;
	switch (prepared.action) {
	case SVM_NESTED_SYNTHETIC_REPLAY:
		return (svm_nested_l2_resume(vcpu));
	case SVM_NESTED_SYNTHETIC_INJECT:
		ctrl->eventinj = prepared.eventinj;
		error = svm_nested_l2_resume(vcpu);
		break;
	case SVM_NESTED_SYNTHETIC_REFLECT:
		/* EVENTINJ does not honor L1's exception intercept bitmap. */
		ctrl->exitcode = prepared.exitcode;
		ctrl->exitinfo1 = prepared.exitinfo1;
		ctrl->exitinfo2 = 0;
		ctrl->exitintinfo = 0;
		error = svm_nested_l2_reflect(vcpu);
		break;
	default:
		return (EPROTO);
	}
	if (error != 0)
		*ctrl = before;
	return (error);
}

/* MSRs that VMRUN does not bank are shared by L1 and L2. */
static enum svm_nested_l2_msr_write_result
svm_nested_l2_shared_msr_read(struct svm_vcpu *vcpu, u_int num,
    uint64_t *value)
{
	bool retu;

	if (lapic_msr(num)) {
		retu = false;
		return (lapic_rdmsr(vcpu->vcpu, num, value, &retu) == 0 &&
		    !retu ? SVM_NESTED_L2_MSR_APPLIED : SVM_NESTED_L2_MSR_GP);
	}

	switch (num) {
	case MSR_MCG_CAP:
	case MSR_MCG_STATUS:
	case MSR_SYSCFG:
	case MSR_AMDK8_IPM:
	case MSR_EXTFEATURES:
		*value = 0;
		return (SVM_NESTED_L2_MSR_APPLIED);
	case MSR_MTRRcap:
	case MSR_MTRRdefType:
	case MSR_MTRR4kBase ... MSR_MTRR4kBase + 7:
	case MSR_MTRR16kBase ... MSR_MTRR16kBase + 1:
	case MSR_MTRR64kBase:
	case MSR_MTRRVarBase ... MSR_MTRRVarBase +
	    (VMM_MTRR_VAR_MAX * 2) - 1:
		return (vm_rdmtrr(&vcpu->mtrr, num, value) == 0 ?
		    SVM_NESTED_L2_MSR_APPLIED : SVM_NESTED_L2_MSR_GP);
	default:
		return (SVM_NESTED_L2_MSR_UNSUPPORTED);
	}
}

static enum svm_nested_l2_msr_write_result
svm_nested_l2_shared_msr_write(struct svm_vcpu *vcpu, u_int num,
    uint64_t value)
{

	switch (num) {
	case MSR_MCG_CAP:
	case MSR_MCG_STATUS:
	case MSR_SYSCFG:
	case MSR_AMDK8_IPM:
	case MSR_EXTFEATURES:
	case MSR_K8_UCODE_UPDATE:
		return (SVM_NESTED_L2_MSR_APPLIED);
	case MSR_MTRRcap:
	case MSR_MTRRdefType:
	case MSR_MTRR4kBase ... MSR_MTRR4kBase + 7:
	case MSR_MTRR16kBase ... MSR_MTRR16kBase + 1:
	case MSR_MTRR64kBase:
	case MSR_MTRRVarBase ... MSR_MTRRVarBase +
	    (VMM_MTRR_VAR_MAX * 2) - 1:
		return (vm_wrmtrr(&vcpu->mtrr, num, value,
		    vm_mtrr_maxphyaddr(cpu_maxphyaddr)) == 0 ?
		    SVM_NESTED_L2_MSR_APPLIED : SVM_NESTED_L2_MSR_GP);
	default:
		return (SVM_NESTED_L2_MSR_UNSUPPORTED);
	}
}

static int
svm_nested_l2_inject_gp(struct svm_vcpu *vcpu)
{

	return (svm_nested_l2_synthetic_exception(vcpu, IDT_GP, true, 0));
}

static int
svm_nested_l2_cr8(struct svm_vcpu *vcpu, uint64_t code, uint64_t info1)
{
	static const int gpr[] = {
		VM_REG_GUEST_RAX, VM_REG_GUEST_RCX, VM_REG_GUEST_RDX,
		VM_REG_GUEST_RBX, VM_REG_GUEST_RSP, VM_REG_GUEST_RBP,
		VM_REG_GUEST_RSI, VM_REG_GUEST_RDI, VM_REG_GUEST_R8,
		VM_REG_GUEST_R9, VM_REG_GUEST_R10, VM_REG_GUEST_R11,
		VM_REG_GUEST_R12, VM_REG_GUEST_R13, VM_REG_GUEST_R14,
		VM_REG_GUEST_R15,
	};
	struct vm_guest_paging paging;
	struct vmcb *vmcb02;
	uint64_t value;
	uint8_t reg;
	bool l1_intr_masking, write;

	vmcb02 = vcpu->nested_vmcb02;
	l1_intr_masking = vcpu->nested_vmcb12->ctrl.v_intr_masking != 0;
	write = code == 0x18;
	if (!decode_assist() ||
	    !svm_nested_cr8_operand(info1, write, &reg) ||
	    vmcb02->ctrl.nrip <= vmcb02->state.rip ||
	    vmcb02->ctrl.nrip - vmcb02->state.rip > VIE_INST_SIZE)
		return (EPROTO);
	if (write) {
		if (svm_getreg(vcpu, gpr[reg], &value) != 0)
			return (EPROTO);
		svm_paging_info(vmcb02, &paging);
		if (paging.cpu_mode != CPU_MODE_64BIT)
			value = (uint32_t)value;
		if (value > 15)
			return (svm_nested_l2_inject_gp(vcpu));
		if (!l1_intr_masking)
			vlapic_set_cr8(vm_lapic(vcpu->vcpu), value);
		vmcb02->ctrl.v_tpr = value;
	} else {
		value = l1_intr_masking ? vmcb02->ctrl.v_tpr :
		    vlapic_get_cr8(vm_lapic(vcpu->vcpu));
		if (svm_setreg(vcpu, gpr[reg], value) != 0)
			return (EPROTO);
	}
	vmcb02->state.rip = vmcb02->ctrl.nrip;
	return (svm_nested_l2_resume(vcpu));
}

static int
svm_nested_l2_inst_emul(struct svm_vcpu *vcpu, struct vmcb *vmcb02,
    uint64_t l1_gpa)
{
	struct vm_exit *vmexit;
	int error;

	if ((vmcb02->ctrl.exitintinfo & VMCB_EVENTINJ_VALID) != 0)
		return (svm_nested_l2_resume(vcpu));
	error = svm_nested_l2_resume(vcpu);
	if (error != 0)
		return (error);
	vmexit = vm_exitinfo(vcpu->vcpu);
	vmexit->rip = vmcb02->state.rip;
	vmexit->inst_length = 0;
	svm_handle_inst_emul(vmcb02, l1_gpa, vmexit);
	return (0);
}

static int
svm_nested_l2_paging(struct svm_vcpu *vcpu, struct vmcb *vmcb02,
    uint64_t l1_gpa, int fault_type)
{
	struct vm_exit *vmexit;
	int error;

	if ((vmcb02->ctrl.exitintinfo & VMCB_EVENTINJ_VALID) != 0)
		return (svm_nested_l2_resume(vcpu));
	error = svm_nested_l2_resume(vcpu);
	if (error != 0)
		return (error);
	vmexit = vm_exitinfo(vcpu->vcpu);
	vmexit->exitcode = VM_EXITCODE_PAGING;
	vmexit->rip = vmcb02->state.rip;
	vmexit->inst_length = 0;
	vmexit->u.paging.gpa = l1_gpa;
	vmexit->u.paging.fault_type = fault_type;
	return (0);
}

/* An L2 exit reaches this sleepable, frozen boundary before L1 bitmap reads. */
static int
svm_nested_l2_exit(struct svm_vcpu *vcpu)
{
	struct svm_nested_bitmap_reader reader;
	struct svm_nested_npt_result npt;
	struct svm_nested_portio portio;
	struct svm_nested_vmcb12_view view;
	enum svm_nested_l0_debug_action debug_action;
	enum svm_nested_l2_msr_write_result msr_write;
	struct vmcb *vmcb02;
	uint64_t code, info1, info2, l1_info1, msr_value;
	uint8_t access;
	bool intercepted;
	int error, retry;

	if (!vcpu->nested_active || vcpu->nested_npt02 == NULL ||
	    vcpu->nested_pending.kind != SVM_NESTED_L2_EXIT)
		return (EPROTO);
	vmcb02 = vcpu->nested_vmcb02;
	code = vmcb02->ctrl.exitcode;
	info1 = vmcb02->ctrl.exitinfo1;
	info2 = vmcb02->ctrl.exitinfo2;
	/* Classify exits caused by L0 hardware/state before L1 intercepts. */
	switch (svm_nested_l2_l0_exit_action(code)) {
	case SVM_NESTED_L2_RESUME:
		return (svm_nested_l2_resume(vcpu));
	case SVM_NESTED_L2_REPORT_L0: {
		struct vm_exit *vmexit;
		uint64_t rip;

		/* These external L0 events cannot be attributed to L1. */
		rip = vmcb02->state.rip;
		error = svm_nested_l2_resume(vcpu);
		if (error != 0)
			return (error);
		vmexit = vm_exitinfo(vcpu->vcpu);
		vmexit->rip = rip;
		svm_nested_l2_l0_exit_info(code, &info1, &info2);
		vm_exit_svm(vmexit, code, info1, info2);
		return (0);
	}
	case SVM_NESTED_L2_MACHINE_CHECK:
		/* Match the ordinary SVM path: the host owns machine checks. */
		__asm __volatile("int $18");
		return (svm_nested_l2_resume(vcpu));
	case SVM_NESTED_L2_FAIL_L0:
		/* A rejected VMCB02 is an L0 composition failure, not an L1 exit. */
		return (EPROTO);
	case SVM_NESTED_L2_ROUTE:
		break;
	default:
		return (EPROTO);
	}
	if (code == VMCB_EXIT_SHUTDOWN)
		return (svm_nested_l2_shutdown(vcpu));
	if (code == VMCB_EXIT_NPF) {
		SDT_PROBE5(vmm, svm, nested, npf, vcpu->sc,
		    vcpu->vcpuid, info2, info1, vcpu->nested_npt12_root_gpa);
		/* A reserved bit in L0's NPT02 is an L0 defect, not an L1 NPF. */
		if ((info1 & VMCB_NPF_INFO1_RSV) != 0)
			return (EPROTO);
		access = (info1 & VMCB_NPF_INFO1_ID) != 0 ?
		    SVM_NESTED_NPT_EXECUTE :
		    (info1 & VMCB_NPF_INFO1_W) != 0 ?
		    SVM_NESTED_NPT_WRITE : SVM_NESTED_NPT_READ;
		if (!vcpu->nested_vmcb12->ctrl.np_enable) {
			/* Without NPT12, L2 physical addresses are L1 physical. */
			if (!vm_mem_allocated(vcpu->vcpu, info2) &&
			    !ppt_is_mmio(vcpu->sc->vm, info2) &&
			    svm_npf_emul_fault(info1))
				return (svm_nested_l2_inst_emul(vcpu, vmcb02,
				    info2));
			error = svm_nested_npt_root_populate(
			    vcpu->nested_npt02, vcpu->vcpu,
			    info2 & ~PAGE_MASK, info2 & ~PAGE_MASK,
			    SVM_NESTED_NPT_READ | SVM_NESTED_NPT_WRITE |
			    SVM_NESTED_NPT_EXECUTE, access);
			if (error == EACCES)
				return (svm_nested_l2_paging(vcpu, vmcb02,
				    info2, npf_fault_type(info1)));
			if (error != 0)
				return (error);
			return (svm_nested_l2_resume(vcpu));
		}
		for (retry = 0; retry < 8; retry++) {
			error = svm_nested_npt_root_resolve(vcpu->nested_npt02,
			    vcpu->vcpu, vcpu->nested_npt12_root_gpa, info2,
			    access, svm_nested_physical_width(
			    vm_mtrr_maxphyaddr(cpu_maxphyaddr)),
			    (amd_feature & AMDID_PAGE1GB) != 0, &npt);
			if (error != EAGAIN)
				break;
		}
		/* L1 kept changing NPT12.  Refault on the next L2 entry. */
		if (error == EAGAIN)
			return (svm_nested_l2_resume(vcpu));
		if (error == ENXIO && svm_npf_emul_fault(info1) &&
		    !ppt_is_mmio(vcpu->sc->vm, npt.l1_gpa))
			return (svm_nested_l2_inst_emul(vcpu, vmcb02,
			    npt.l1_gpa));
		if (error == EACCES)
			return (svm_nested_l2_paging(vcpu, vmcb02,
			    npt.l1_gpa, npf_fault_type(info1)));
		if (error != 0)
			return (error);
		if (npt.outcome == SVM_NESTED_NPT_TRANSLATED) {
			return (svm_nested_l2_resume(vcpu));
		}
		error = svm_nested_npt_reflect_info1(&npt, info1,
		    &l1_info1);
		if (error != 0)
			return (error);
		vmcb02->ctrl.exitinfo1 = l1_info1;
		intercepted = true;
	} else {
		if (!svm_nested_vmcb12_view_from_vmcb(&view,
		    vcpu->nested_vmcb12, vcpu->nested_vmcb12_gpa,
		    vcpu->nested_msr.hsave_gpa))
			return (EPROTO);
		error = svm_nested_bitmap_reader_init(vcpu->vcpu, &reader);
		if (error != 0)
			return (error);
		error = svm_nested_exit_intercepted(&view, &reader, code,
		    info1, (uint32_t)vcpu->swctx.sctx_rcx, &intercepted);
		if (error != 0)
			return (error);
	}
	/* L0's debug step and TF shadow exits precede an L1 intercept. */
	debug_action = svm_nested_l0_debug_exit(code,
	    vcpu->vmcb->ctrl.intercept[VMCB_EXC_INTCPT],
	    vcpu->vmcb->ctrl.intercept[VMCB_CTRL1_INTCPT],
	    vcpu->nested_debug_step_l2,
	    (vmcb02->state.dr6 & DBREG_DR6_BS) != 0);
	if (debug_action != SVM_NESTED_L0_DEBUG_NONE)
		intercepted = false;
	/* An L0 breakpoint exit wins even when L1 also intercepts #BP. */
	if (code == 0x40 + IDT_BP &&
	    (vcpu->vmcb->ctrl.intercept[VMCB_EXC_INTCPT] & BIT(IDT_BP)) != 0)
		intercepted = false;
	if (!intercepted) {
		uint8_t cr;

		/* Complete interrupted event delivery before emulating an L2 exit. */
		if ((vmcb02->ctrl.exitintinfo & VMCB_EVENTINJ_VALID) != 0)
			return (svm_nested_l2_resume(vcpu));
		/*
		 * The guest CPU profile implements CR0-CR4 and CR8 only.
		 * AMD APM volume 2, 3.1.4 specifies #UD for reserved and
		 * unimplemented control registers.
		 */
		if (code < 0x20) {
			cr = code & 0xf;
			if (cr == 1 || (cr >= 5 && cr <= 7) || cr >= 9)
				return (svm_nested_l2_synthetic_exception(vcpu,
				    IDT_UD, false, 0));
		}
		if (code == 0x08 || code == 0x18)
			return (svm_nested_l2_cr8(vcpu, code, info1));
		if (debug_action == SVM_NESTED_L0_DEBUG_PUSHF ||
		    debug_action == SVM_NESTED_L0_DEBUG_POPF) {
			uint32_t bit;

			/* Restart once with TF set, then report the following #DB. */
			bit = debug_action == SVM_NESTED_L0_DEBUG_PUSHF ?
			    VMCB_INTCPT_PUSHF :
			    VMCB_INTCPT_POPF;
			vmcb02->ctrl.intercept[VMCB_CTRL1_INTCPT] &= ~bit;
			vmcb02->state.rflags |= PSL_T;
			if (debug_action == SVM_NESTED_L0_DEBUG_PUSHF)
				vcpu->dbg.pushf_sstep = 1;
			else
				vcpu->dbg.popf_sstep = 1;
			return (svm_nested_l2_resume(vcpu));
		}
		if (debug_action == SVM_NESTED_L0_DEBUG_STEP) {
			struct vm_exit *vmexit;
			uint64_t rip;

			rip = vmcb02->state.rip;
			vmcb02->state.dr6 &= ~DBREG_DR6_BS;
			error = svm_nested_l2_resume(vcpu);
			if (error != 0)
				return (error);
			vmexit = vm_exitinfo(vcpu->vcpu);
			vmexit->exitcode = VM_EXITCODE_DB;
			vmexit->rip = rip;
			vmexit->inst_length = 0;
			bzero(&vmexit->u.dbg, sizeof(vmexit->u.dbg));
			vmexit->u.dbg.trace_trap = 1;
			if (vcpu->dbg.popf_sstep) {
				vcpu->dbg.popf_sstep = 0;
				vcpu->dbg.rflags_tf =
				    vmcb02->state.rflags & PSL_T;
			} else if (vcpu->dbg.pushf_sstep) {
				vcpu->dbg.pushf_sstep = 0;
				vmexit->u.dbg.pushf_intercept = 1;
				vmexit->u.dbg.tf_shadow_val =
				    vcpu->dbg.rflags_tf;
				svm_paging_info(vmcb02,
				    &vmexit->u.dbg.paging);
			}
			return (0);
		}
		if (code == 0x40 + IDT_BP &&
		    (vcpu->vmcb->ctrl.intercept[VMCB_EXC_INTCPT] &
		    BIT(IDT_BP)) != 0) {
			struct vm_exit *vmexit;
			uint64_t rip;

			if (vmcb02->ctrl.nrip <= vmcb02->state.rip ||
			    vmcb02->ctrl.nrip - vmcb02->state.rip >
			    VIE_INST_SIZE)
				return (EPROTO);
			rip = vmcb02->state.rip;
			error = svm_nested_l2_resume(vcpu);
			if (error != 0)
				return (error);
			vmexit = vm_exitinfo(vcpu->vcpu);
			vmexit->exitcode = VM_EXITCODE_BPT;
			vmexit->rip = rip;
			vmexit->inst_length = 0;
			vmexit->u.bpt.inst_length = vmcb02->ctrl.nrip - rip;
			return (0);
		}
		if (code >= 0x40 && code < 0x60) {
			uint64_t eventinj;

			error = svm_nested_l2_fault_injection(code - 0x40,
			    info1, vmcb02->ctrl.eventinj,
			    vmcb02->ctrl.exitintinfo, &eventinj);
			if (error == EAGAIN)
				return (svm_nested_l2_resume(vcpu));
			if (error != 0)
				return (error);
			if (code - 0x40 == IDT_PF)
				vmcb02->state.cr2 = info2;
			vmcb02->ctrl.eventinj = eventinj;
			return (svm_nested_l2_resume(vcpu));
		}
		if (code == VMCB_EXIT_HLT || code == VMCB_EXIT_PAUSE) {
			struct vm_exit *vmexit;
			uint64_t rip;

			if (vmcb02->ctrl.nrip <= vmcb02->state.rip ||
			    vmcb02->ctrl.nrip - vmcb02->state.rip >
			    VIE_INST_SIZE)
				return (EPROTO);
			rip = vmcb02->state.rip;
			vmcb02->state.rip = vmcb02->ctrl.nrip;
			error = svm_nested_l2_resume(vcpu);
			if (error != 0)
				return (error);
			vmexit = vm_exitinfo(vcpu->vcpu);
			vmexit->exitcode = code == VMCB_EXIT_HLT ?
			    VM_EXITCODE_HLT : VM_EXITCODE_PAUSE;
			vmexit->rip = rip;
			vmexit->inst_length = vmcb02->ctrl.nrip - rip;
			if (code == VMCB_EXIT_HLT)
				vmexit->u.hlt.rflags = vmcb02->state.rflags;
			return (0);
		}
		if (code == VMCB_EXIT_IO && (info1 & BIT(2)) == 0) {
			struct vm_exit *vmexit;
			uint64_t rip;

			if (svm_nested_portio_decode(info1, vmcb02->state.rip,
			    vmcb02->ctrl.nrip, &portio) != 0)
				return (EPROTO);
			rip = vmcb02->state.rip;
			vmcb02->state.rip = portio.next_rip;
			error = svm_nested_l2_resume(vcpu);
			if (error != 0)
				return (error);
			vmexit = vm_exitinfo(vcpu->vcpu);
			vmexit->exitcode = VM_EXITCODE_INOUT;
			vmexit->rip = rip;
			vmexit->inst_length = portio.next_rip - rip;
			vmexit->u.inout.in = portio.in;
			vmexit->u.inout.string = 0;
			vmexit->u.inout.rep = 0;
			vmexit->u.inout.bytes = portio.bytes;
			vmexit->u.inout.port = portio.port;
			vmexit->u.inout.eax = (uint32_t)vmcb02->state.rax;
			return (0);
		}
		if (code == VMCB_EXIT_IO && (info1 & BIT(2)) != 0) {
			struct vm_exit *vmexit;
			uint64_t rip;

			/*
			 * vm_copy_setup() walks L2 guest page tables and translates
			 * the final operand through svm_translate_gpa().  That backend
			 * walks NPT12 and reflects a denied operand to L1 before
			 * userland touches guest memory.
			 */
			if (vmcb02->ctrl.nrip <= vmcb02->state.rip ||
			    vmcb02->ctrl.nrip - vmcb02->state.rip >
			    VIE_INST_SIZE)
				return (EPROTO);
			rip = vmcb02->state.rip;
			error = svm_nested_l2_resume(vcpu);
			if (error != 0)
				return (error);
			vmexit = vm_exitinfo(vcpu->vcpu);
			vmexit->rip = rip;
			vmexit->inst_length = vmcb02->ctrl.nrip - rip;
			(void)svm_handle_io(vcpu, vmcb02, vmexit);
			return (0);
		}
		if (code == VMCB_EXIT_MSR && info1 == 0) {
			if (svm_nested_l2_vmcb_msr_read(vmcb02,
			    (uint32_t)vcpu->swctx.sctx_rcx, rdtsc(),
			    &msr_value))
				msr_write = SVM_NESTED_L2_MSR_APPLIED;
			else
				msr_write = svm_nested_l2_shared_msr_read(vcpu,
				    (uint32_t)vcpu->swctx.sctx_rcx, &msr_value);
			if (msr_write != SVM_NESTED_L2_MSR_APPLIED)
				return (svm_nested_l2_inject_gp(vcpu));
			if (vmcb02->ctrl.nrip <= vmcb02->state.rip ||
			    vmcb02->ctrl.nrip - vmcb02->state.rip >
			    VIE_INST_SIZE)
				return (EPROTO);
			vmcb02->state.rax = (uint32_t)msr_value;
			vcpu->swctx.sctx_rdx = (uint32_t)(msr_value >> 32);
			vmcb02->state.rip = vmcb02->ctrl.nrip;
			return (svm_nested_l2_resume(vcpu));
		}
		if (code == VMCB_EXIT_MSR && info1 == 1) {
			struct vm_exit *vmexit;
			uint64_t rip;
			bool retu;

			if (vmcb02->ctrl.nrip <= vmcb02->state.rip ||
			    vmcb02->ctrl.nrip - vmcb02->state.rip >
			    VIE_INST_SIZE)
				return (EPROTO);
			msr_value = (uint64_t)(uint32_t)vcpu->swctx.sctx_rdx
			    << 32 | (uint32_t)vmcb02->state.rax;
			if ((uint32_t)vcpu->swctx.sctx_rcx == MSR_TSC) {
				svm_set_tsc_offset(vcpu, msr_value - rdtsc() -
				    vcpu->nested_vmcb12->ctrl.tsc_offset);
				vpvclock_vcpu_update(vcpu->vcpu);
				msr_write = SVM_NESTED_L2_MSR_APPLIED;
			} else if ((uint32_t)vcpu->swctx.sctx_rcx == MSR_EFER)
				msr_write = svm_nested_l2_efer_write(vmcb02,
				    msr_value,
				    vm_cpuid_capability(vcpu->vcpu, VCC_NO_EXECUTE),
				    vm_cpuid_capability(vcpu->vcpu, VCC_FFXSR),
				    vm_cpuid_capability(vcpu->vcpu, VCC_TCE));
			else if (lapic_msr((uint32_t)vcpu->swctx.sctx_rcx)) {
				/* The L0 vLAPIC is shared across VMRUN boundaries. */
				retu = false;
				error = lapic_wrmsr(vcpu->vcpu,
				    (uint32_t)vcpu->swctx.sctx_rcx, msr_value,
				    &retu);
				msr_write = error == 0 ? SVM_NESTED_L2_MSR_APPLIED :
				    SVM_NESTED_L2_MSR_GP;
				if (error == 0 && retu) {
					/* An ICR write can request userspace IPI handling. */
					vmexit = vm_exitinfo(vcpu->vcpu);
					if (vmexit->exitcode != VM_EXITCODE_IPI)
						return (EPROTO);
					rip = vmcb02->state.rip;
					vmcb02->state.rip = vmcb02->ctrl.nrip;
					error = svm_nested_l2_resume(vcpu);
					if (error != 0)
						return (error);
					vmexit->rip = rip;
					vmexit->inst_length = vmcb02->ctrl.nrip - rip;
					return (0);
				}
			}
			else
				msr_write = svm_nested_l2_vmcb_msr_write(vmcb02,
				    (uint32_t)vcpu->swctx.sctx_rcx, msr_value);
			if (msr_write == SVM_NESTED_L2_MSR_UNSUPPORTED)
				msr_write = svm_nested_l2_shared_msr_write(vcpu,
				    (uint32_t)vcpu->swctx.sctx_rcx, msr_value);
			if (msr_write == SVM_NESTED_L2_MSR_APPLIED) {
				if ((uint32_t)vcpu->swctx.sctx_rcx == MSR_PAT &&
				    !vcpu->nested_vmcb12->ctrl.np_enable) {
					vcpu->vmcb->state.g_pat = vmcb02->state.g_pat;
					svm_set_dirty(vcpu, VMCB_CACHE_NP);
				}
				vmcb02->state.rip = vmcb02->ctrl.nrip;
				return (svm_nested_l2_resume(vcpu));
			}
			return (svm_nested_l2_inject_gp(vcpu));
		}
		if (code == VMCB_EXIT_CPUID) {
			uint64_t rax, rbx, rcx, rdx;

			if (vmcb02->ctrl.nrip <= vmcb02->state.rip ||
			    vmcb02->ctrl.nrip - vmcb02->state.rip >
			    VIE_INST_SIZE)
				return (EPROTO);
			rax = vmcb02->state.rax;
			rbx = vcpu->swctx.sctx_rbx;
			rcx = vcpu->swctx.sctx_rcx;
			rdx = vcpu->swctx.sctx_rdx;
			if (x86_emulate_cpuid_nested_svm_l2(vcpu->vcpu,
			    vmcb02->state.cr4, &rax, &rbx, &rcx, &rdx) == 0)
				return (EPROTO);
			vmcb02->state.rax = rax;
			vcpu->swctx.sctx_rbx = rbx;
			vcpu->swctx.sctx_rcx = rcx;
			vcpu->swctx.sctx_rdx = rdx;
			vmcb02->state.rip = vmcb02->ctrl.nrip;
			return (svm_nested_l2_resume(vcpu));
		}
		if (code == VMCB_EXIT_VMRUN || code == VMCB_EXIT_VMLOAD ||
		    code == VMCB_EXIT_VMSAVE || code == VMCB_EXIT_STGI ||
		    code == VMCB_EXIT_CLGI || code == VMCB_EXIT_INVLPGA ||
		    code == VMCB_EXIT_MONITOR || code == VMCB_EXIT_MWAIT ||
		    code == VMCB_EXIT_SKINIT || code == VMCB_EXIT_ICEBP ||
		    code == VMCB_EXIT_VMMCALL) {
			/* Match the ordinary L0 #UD policy for these instructions. */
			return (svm_nested_l2_synthetic_exception(vcpu,
			    IDT_UD, false, 0));
		}
		if (code == VMCB_EXIT_INVD || code == VMCB_EXIT_WBINVD) {
			if (vmcb02->ctrl.nrip <= vmcb02->state.rip ||
			    vmcb02->ctrl.nrip - vmcb02->state.rip >
			    VIE_INST_SIZE)
				return (EPROTO);
			vmcb02->state.rip = vmcb02->ctrl.nrip;
			return (svm_nested_l2_resume(vcpu));
		}
		return (EOPNOTSUPP);
	}
	return (svm_nested_l2_reflect(vcpu));
}

static int
svm_handle_internal_exit(void *vcpui)
{
	struct svm_nested_instruction_pending pending;
	struct svm_nested_vmcb12_view view;
	struct vmcb_ctrl *ctrl;
	struct svm_vcpu *vcpu;
	uint64_t pending_event, vmcb_gpa;
	bool fault;
	int error;

	vcpu = vcpui;
	if (vcpu == NULL ||
	    vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	pending = vcpu->nested_pending;
	vcpu->nested_pending.kind = SVM_NESTED_INSTRUCTION_NONE;
	if (pending.kind == SVM_NESTED_INIT_GIF_RECHECK) {
		if ((vcpu->startup_claim_phase !=
		    SVM_STARTUP_CLAIM_INIT_REFLECTED &&
		    vcpu->startup_claim_phase != SVM_STARTUP_CLAIM_HELD) ||
		    vcpu->startup_claim.kind != VMM_STARTUP_EVENT_INIT ||
		    !vcpu->nested_gif || vcpu->nested_active)
			return (EPROTO);
		return (0);
	}
	SDT_PROBE5(vmm, svm, nested, instruction, vcpu->sc,
	    vcpu->vcpuid, pending.kind, pending.vmcb_gpa, pending.rip);
	if (pending.kind == SVM_NESTED_INSTRUCTION_NONE ||
	    !vcpu->nested_msr.exposed || !vcpu->nested_msr.svme)
		return (EPROTO);
	if (pending.kind == SVM_NESTED_L2_EXIT) {
		vcpu->nested_pending.kind = SVM_NESTED_L2_EXIT;
		error = svm_nested_l2_exit(vcpu);
		if (error == ENOMEM) {
			/* An NPT02 alias failure is retryable after memory recovers. */
			error = svm_nested_l2_resume(vcpu);
			if (error == 0)
				return (ENOMEM);
		}
		if (error != 0) {
			SDT_PROBE5(vmm, svm, nested, failure, vcpu->sc,
			    vcpu->vcpuid, error,
			    (vcpu->nested_vmcb02 != NULL ?
			    vcpu->nested_vmcb02->ctrl.exitcode : 0), pending.kind);
			vcpu->nested_poisoned = true;
		}
		return (error);
	}
	if (pending.kind == SVM_NESTED_L2_PENDING_EVENT) {
		if (!vcpu->nested_active || vcpu->nested_vmcb02 == NULL ||
		    vcpu->nested_vmcb12 == NULL)
			return (EPROTO);
		ctrl = &vcpu->nested_vmcb02->ctrl;
		/* Recheck after freezing: a newly pending NMI takes priority. */
		pending_event = svm_nested_pending_event(vcpu,
		    vm_lapic(vcpu->vcpu));
		if (pending_event == 0)
			return (svm_nested_l2_resume(vcpu));
		ctrl->exitcode = pending_event;
		ctrl->exitinfo1 = 0;
		ctrl->exitinfo2 = 0;
		ctrl->exitintinfo = 0;
		ctrl->nrip = 0;
		error = svm_nested_l2_reflect(vcpu);
		if (error != 0)
			vcpu->nested_poisoned = true;
		return (error);
	}
	error = svm_nested_instruction_operand(vcpu, &pending, &vmcb_gpa,
	    &fault);
	if (error != 0) {
		SDT_PROBE5(vmm, svm, nested, failure, vcpu->sc,
		    vcpu->vcpuid, error, pending.vmcb_gpa, pending.kind);
		return (error);
	}
	if (fault)
		return (0);

	switch (pending.kind) {
	case SVM_NESTED_INSTRUCTION_VMLOAD:
		error = svm_nested_vmcb12_read(vcpu->vcpu,
		    vmcb_gpa, svm_nested_physical_width(
		    vm_mtrr_maxphyaddr(cpu_maxphyaddr)),
		    vcpu->nested_vmcb12);
		if (error != 0)
			break;
		svm_nested_vmcb_aux_copy(vcpu->vmcb, vcpu->nested_vmcb12);
		svm_set_dirty(vcpu, 0xffffffff);
		break;
	case SVM_NESTED_INSTRUCTION_VMSAVE:
		error = svm_nested_vmcb12_aux_save(vcpu->vcpu,
		    vmcb_gpa, svm_nested_physical_width(
		    vm_mtrr_maxphyaddr(cpu_maxphyaddr)),
		    vcpu->vmcb);
		break;
	case SVM_NESTED_INSTRUCTION_VMRUN:
		error = svm_nested_vmcb12_read(vcpu->vcpu,
		    vmcb_gpa, svm_nested_physical_width(
		    vm_mtrr_maxphyaddr(cpu_maxphyaddr)),
		    vcpu->nested_vmcb12);
		if (error != 0)
			break;
		if (!svm_nested_vmcb12_view_from_vmcb(&view,
		    vcpu->nested_vmcb12, vmcb_gpa,
		    vcpu->nested_msr.hsave_gpa))
			return (EPROTO);
		if (!svm_nested_vmcb12_view_valid(&view,
		    svm_nested_physical_width(
		    vm_mtrr_maxphyaddr(cpu_maxphyaddr)), true)) {
			error = svm_nested_vmcb12_invalid_exit(vcpu->vcpu,
			    vmcb_gpa,
			    svm_nested_physical_width(
			    vm_mtrr_maxphyaddr(cpu_maxphyaddr)));
			if (error == 0)
				vcpu->nested_gif = false;
			break;
		}
		if (vcpu->nested_npt02 == NULL) {
			error = svm_nested_npt_root_create(
			    VM_MAXUSER_ADDRESS_LA48, &vcpu->nested_npt02);
		} else {
			error = svm_nested_npt_root_clear(vcpu->nested_npt02);
		}
		if (error != 0)
			return (error);
		/*
		 * Build a private VMCB02 from the accepted VMCB12.  Its ASID is
		 * deliberately invalidated below: only the CPU-bound entry path
		 * may allocate a distinct L2 ASID and publish VMCB residency.
		 */
		error = svm_nested_vmcb02_compose(vcpu->nested_vmcb02,
		    vcpu->vmcb, vcpu->nested_vmcb12,
		    svm_nested_npt_root_pa(vcpu->nested_npt02),
		    vtophys(vcpu->sc->iopm_bitmap),
		    vtophys(vcpu->sc->nested_msr_bitmap), 1);
		if (error != 0)
			return (error);
		error = svm_nested_vnmi_prepare(vcpu->nested_vmcb02,
		    vmcb_gpa, vcpu->nested_vnmi_gpas);
		if (error != 0)
			return (error);
		vcpu->nested_vmcb02->ctrl.asid = 0;
		vcpu->nested_asid.gen = 0;
		vcpu->nested_eptgen = 0;
		vcpu->nested_vmcb12_gpa = vmcb_gpa;
		vcpu->nested_npt12_root_gpa = view.npt_root_gpa;
		vcpu->nested_l1_next_rip = pending.next_rip;
		vcpu->nested_active = true;
		return (svm_nested_l2_resume(vcpu));
	default:
		return (EPROTO);
	}
	if (error == EINVAL || error == EFAULT) {
		svm_nested_instruction_resume(vcpu, pending.rip);
		vm_inject_gp(vcpu->vcpu);
		return (0);
	}
	if (error != 0) {
		SDT_PROBE5(vmm, svm, nested, failure, vcpu->sc,
		    vcpu->vcpuid, error, vmcb_gpa, pending.kind);
		return (error);
	}
	svm_nested_instruction_resume(vcpu, pending.next_rip);
	return (0);
}

static int
svm_get_cpu_compat(void *vcpui, struct vm_cpu_compat *compat)
{
	struct svm_vcpu *vcpu;

	vcpu = vcpui;
	if (vcpu == NULL || compat == NULL)
		return (EINVAL);
	if (!vcpu->nested_msr.exposed)
		return (0);
	/* Bind restore to the nested wire schema and host virtual NMI support. */
	compat->nested_capability_signature = UINT64_C(0x53564d0000000000) |
	    ((svm_feature & AMD_CPUID_SVM_VNMI) != 0 ? 1U : 0U);
	compat->nested_schema_signature = UINT64_C(0x53564d0000000000) |
	    SVM_NESTED_STATE_SCHEMA_VERSION;
	compat->flags |= VM_CPU_COMPAT_F_NESTED_SVM;
	return (0);
}

static int
svm_nested_memmap_invalidate(void *vcpui)
{
	struct svm_vcpu *vcpu;
	int error;

	vcpu = vcpui;
	if (vcpu->nested_npt02 == NULL)
		return (0);
	error = svm_nested_npt_root_clear(vcpu->nested_npt02);
	if (error != 0)
		return (error);
	/* The same NPT root can be resumed after this frozen boundary. */
	vcpu->nested_asid.gen = 0;
	vcpu->nested_eptgen = 0;
	return (0);
}

const struct vmm_ops vmm_ops_amd = {
	.modinit	= svm_modinit,
	.modcleanup	= svm_modcleanup,
	.modresume	= svm_modresume,
	.modsuspend	= svm_modsuspend,
	.init		= svm_init,
	.run		= svm_run,
	.handle_internal_exit = svm_handle_internal_exit,
	.cleanup	= svm_cleanup,
	.vcpu_init	= svm_vcpu_init,
	.startup_kernel_actions_ready = svm_startup_kernel_actions_ready,
	.vcpu_startup_event_step = svm_vcpu_startup_event_step,
	.vcpu_event_cleanup_check = svm_vcpu_event_cleanup_check,
	.vcpu_event_cleanup = svm_vcpu_event_cleanup,
	.vcpu_cleanup	= svm_vcpu_cleanup,
	.nested_memmap_invalidate = svm_nested_memmap_invalidate,
	.getreg		= svm_getreg,
	.setreg		= svm_setreg,
	.translate_gpa	= svm_translate_gpa,
	.getdesc	= svm_getdesc,
	.setdesc	= svm_setdesc,
	.getcap		= svm_getcap,
	.setcap		= svm_setcap,
	.get_cpu_compat = svm_get_cpu_compat,
	.vmspace_alloc	= svm_vmspace_alloc,
	.vmspace_free	= svm_vmspace_free,
	.vlapic_init	= svm_vlapic_init,
	.vlapic_cleanup	= svm_vlapic_cleanup,
#ifdef BHYVE_SNAPSHOT
	.vm_snapshot	= svm_vm_snapshot,
	.vcpu_snapshot	= svm_vcpu_snapshot,
	.vm_snapshot_complete = svm_vm_snapshot_complete,
	.restore_tsc	= svm_restore_tsc,
#endif
};
