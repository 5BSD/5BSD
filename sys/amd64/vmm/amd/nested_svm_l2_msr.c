/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#ifdef _KERNEL
#include <sys/systm.h>
#include <machine/segments.h>
#include <machine/vmm.h>
#else
#include <string.h>
#endif

#include <machine/specialreg.h>

#include "vmcb.h"
#include "nested_svm_l2_msr.h"

#ifdef _KERNEL
CTASSERT(offsetof(struct vmcb, state.efer) == VMCB_OFF_STATE(0xd0));
CTASSERT(offsetof(struct vmcb, state.cr0) == VMCB_OFF_STATE(0x158));
CTASSERT(offsetof(struct vmcb, state.fs.base) == VMCB_OFF_STATE(0x48));
CTASSERT(offsetof(struct vmcb, state.gs.base) == VMCB_OFF_STATE(0x58));
CTASSERT(offsetof(struct vmcb, state.g_pat) == VMCB_OFF_GUEST_PAT);
#endif

bool
svm_nested_l2_vmcb_msr_read(const void *vmcb02, uint32_t msr,
    uint64_t host_tsc, uint64_t *value)
{
	const uint8_t *bytes;
	uint32_t offset;

	if (vmcb02 == NULL || value == NULL)
		return (false);
	switch (msr) {
	case MSR_TSC:
		offset = VMCB_OFF_TSC_OFFSET;
		break;
	case MSR_EFER:
		offset = VMCB_OFF_STATE(0xd0);
		break;
	case MSR_FSBASE:
		offset = VMCB_OFF_STATE(0x48);
		break;
	case MSR_GSBASE:
		offset = VMCB_OFF_STATE(0x58);
		break;
	case MSR_KGSBASE:
		offset = VMCB_OFF_KERNELGBASE;
		break;
	case MSR_STAR:
		offset = VMCB_OFF_STAR;
		break;
	case MSR_LSTAR:
		offset = VMCB_OFF_LSTAR;
		break;
	case MSR_CSTAR:
		offset = VMCB_OFF_CSTAR;
		break;
	case MSR_SF_MASK:
		offset = VMCB_OFF_SFMASK;
		break;
	case MSR_SYSENTER_CS_MSR:
		offset = VMCB_OFF_SYSENTER_CS;
		break;
	case MSR_SYSENTER_ESP_MSR:
		offset = VMCB_OFF_SYSENTER_ESP;
		break;
	case MSR_SYSENTER_EIP_MSR:
		offset = VMCB_OFF_SYSENTER_EIP;
		break;
	case MSR_PAT:
		offset = VMCB_OFF_GUEST_PAT;
		break;
	default:
		return (false);
	}
	bytes = vmcb02;
	memcpy(value, bytes + offset, sizeof(*value));
	if (msr == MSR_TSC)
		*value += host_tsc;
	if (msr == MSR_SF_MASK || msr == MSR_SYSENTER_CS_MSR)
		*value = (uint32_t)*value;
	/* VMRUN requires SVME in the VMCB, but L2 has no virtual SVM. */
	if (msr == MSR_EFER)
		*value &= ~EFER_SVM;
	return (true);
}

static bool
svm_nested_l2_canonical48(uint64_t value)
{
	uint64_t high;

	high = value >> 47;
	return (high == 0 || high == 0x1ffff);
}

bool
svm_nested_l2_pat_valid(uint64_t value)
{
	uint8_t type;
	int i;

	for (i = 0; i < 8; i++) {
		type = value >> (i * 8);
		if (type != 0 && type != 1 && type != 4 && type != 5 &&
		    type != 6 && type != 7)
			return (false);
	}
	return (true);
}

enum svm_nested_l2_msr_write_result
svm_nested_l2_vmcb_msr_write(void *vmcb02, uint32_t msr, uint64_t value)
{
	uint8_t *bytes;
	uint32_t offset;

	if (vmcb02 == NULL)
		return (SVM_NESTED_L2_MSR_UNSUPPORTED);
	switch (msr) {
	case MSR_FSBASE:
		offset = VMCB_OFF_STATE(0x48);
		goto canonical;
	case MSR_GSBASE:
		offset = VMCB_OFF_STATE(0x58);
		goto canonical;
	case MSR_KGSBASE:
		offset = VMCB_OFF_KERNELGBASE;
		goto canonical;
	case MSR_STAR:
		offset = VMCB_OFF_STAR;
		break;
	case MSR_LSTAR:
		offset = VMCB_OFF_LSTAR;
		goto canonical;
	case MSR_CSTAR:
		offset = VMCB_OFF_CSTAR;
		goto canonical;
	case MSR_SF_MASK:
		offset = VMCB_OFF_SFMASK;
		value = (uint32_t)value;	/* Upper half reads as zero. */
		break;
	case MSR_SYSENTER_CS_MSR:
		offset = VMCB_OFF_SYSENTER_CS;
		value = (uint32_t)value; /* AMD reads bits 63:32 as zero. */
		break;
	case MSR_SYSENTER_ESP_MSR:
		offset = VMCB_OFF_SYSENTER_ESP;
		break;
	case MSR_SYSENTER_EIP_MSR:
		offset = VMCB_OFF_SYSENTER_EIP;
		break;
	case MSR_PAT:
		if (!svm_nested_l2_pat_valid(value))
			return (SVM_NESTED_L2_MSR_GP);
		offset = VMCB_OFF_GUEST_PAT;
		break;
	default:
		return (SVM_NESTED_L2_MSR_UNSUPPORTED);
	}
	goto write;
canonical:
	if (!svm_nested_l2_canonical48(value))
		return (SVM_NESTED_L2_MSR_GP);
write:
	bytes = vmcb02;
	memcpy(bytes + offset, &value, sizeof(value));
	return (SVM_NESTED_L2_MSR_APPLIED);
}

enum svm_nested_l2_msr_write_result
svm_nested_l2_efer_write(void *vmcb02, uint64_t value, bool nx,
    bool ffxsr, bool tce)
{
	const uint64_t allowed = EFER_SCE | EFER_LME | EFER_LMA |
	    EFER_NXE | EFER_FFXSR | EFER_TCE;
	uint8_t *bytes;
	uint64_t cr0, old, lma;

	if (vmcb02 == NULL)
		return (SVM_NESTED_L2_MSR_UNSUPPORTED);
	bytes = vmcb02;
	memcpy(&old, bytes + VMCB_OFF_STATE(0xd0), sizeof(old));
	memcpy(&cr0, bytes + VMCB_OFF_STATE(0x158), sizeof(cr0));
	value &= ~0xfeULL;	/* Read-as-zero EFER bits. */
	if ((value & ~allowed) != 0 ||
	    (((old ^ value) & EFER_LME) != 0 && (cr0 & CR0_PG) != 0) ||
	    ((value & EFER_NXE) != 0 && !nx) ||
	    ((value & EFER_FFXSR) != 0 && !ffxsr) ||
	    ((value & EFER_TCE) != 0 && !tce))
		return (SVM_NESTED_L2_MSR_GP);
	lma = (value & EFER_LME) != 0 && (cr0 & CR0_PG) != 0 ?
	    EFER_LMA : 0;
	if ((value & EFER_LMA) != lma)
		return (SVM_NESTED_L2_MSR_GP);
	value |= EFER_SVM;	/* L0 needs physical SVME for VMRUN. */
	memcpy(bytes + VMCB_OFF_STATE(0xd0), &value, sizeof(value));
	return (SVM_NESTED_L2_MSR_APPLIED);
}
