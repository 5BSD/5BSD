/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/amd64/vmm/vmm_x86_startup_vmreg.c"

ATF_TC_WITHOUT_HEAD(register_mapping_is_complete);
ATF_TC_BODY(register_mapping_is_complete, tc)
{
	static const enum vm_reg_name expected[] = {
		VM_REG_GUEST_RFLAGS, VM_REG_GUEST_RIP, VM_REG_GUEST_CR0,
		VM_REG_GUEST_CR2, VM_REG_GUEST_CR3, VM_REG_GUEST_CR4,
		VM_REG_GUEST_EFER, VM_REG_GUEST_RAX, VM_REG_GUEST_RBX,
		VM_REG_GUEST_RCX, VM_REG_GUEST_RDX, VM_REG_GUEST_RSI,
		VM_REG_GUEST_RDI, VM_REG_GUEST_RBP, VM_REG_GUEST_RSP,
		VM_REG_GUEST_R8, VM_REG_GUEST_R9, VM_REG_GUEST_R10,
		VM_REG_GUEST_R11, VM_REG_GUEST_R12, VM_REG_GUEST_R13,
		VM_REG_GUEST_R14, VM_REG_GUEST_R15, VM_REG_GUEST_DR0,
		VM_REG_GUEST_DR1, VM_REG_GUEST_DR2, VM_REG_GUEST_DR3,
		VM_REG_GUEST_DR6, VM_REG_GUEST_DR7,
		VM_REG_GUEST_INTR_SHADOW,
	};
	enum vm_reg_name output;
	unsigned int i;

	(void)tc;
	ATF_REQUIRE_EQ(nitems(expected), VMM_X86_STARTUP_REG_COUNT);
	for (i = 0; i < nitems(expected); i++) {
		output = VM_REG_LAST;
		ATF_CHECK_EQ(vmm_x86_startup_register_vmreg(i, &output), 0);
		ATF_CHECK_EQ(output, expected[i]);
	}
}

ATF_TC_WITHOUT_HEAD(descriptor_mapping_is_complete);
ATF_TC_BODY(descriptor_mapping_is_complete, tc)
{
	static const enum vm_reg_name expected[] = {
		VM_REG_GUEST_CS, VM_REG_GUEST_SS, VM_REG_GUEST_DS,
		VM_REG_GUEST_ES, VM_REG_GUEST_FS, VM_REG_GUEST_GS,
		VM_REG_GUEST_TR, VM_REG_GUEST_LDTR, VM_REG_GUEST_GDTR,
		VM_REG_GUEST_IDTR,
	};
	enum vm_reg_name output;
	unsigned int i;

	(void)tc;
	ATF_REQUIRE_EQ(nitems(expected), VMM_X86_STARTUP_DESC_COUNT);
	for (i = 0; i < nitems(expected); i++) {
		output = VM_REG_LAST;
		ATF_CHECK_EQ(vmm_x86_startup_descriptor_vmreg(i, &output), 0);
		ATF_CHECK_EQ(output, expected[i]);
	}
}

ATF_TC_WITHOUT_HEAD(rejection_preserves_output);
ATF_TC_BODY(rejection_preserves_output, tc)
{
	enum vm_reg_name output;

	(void)tc;
	output = VM_REG_GUEST_RAX;
	ATF_CHECK_EQ(vmm_x86_startup_register_vmreg(-1, &output), EINVAL);
	ATF_CHECK_EQ(output, VM_REG_GUEST_RAX);
	ATF_CHECK_EQ(vmm_x86_startup_register_vmreg(
	    VMM_X86_STARTUP_REG_COUNT, &output), EINVAL);
	ATF_CHECK_EQ(output, VM_REG_GUEST_RAX);
	ATF_CHECK_EQ(vmm_x86_startup_register_vmreg(
	    VMM_X86_STARTUP_REG_RAX, NULL), EINVAL);

	output = VM_REG_GUEST_CS;
	ATF_CHECK_EQ(vmm_x86_startup_descriptor_vmreg(-1, &output), EINVAL);
	ATF_CHECK_EQ(output, VM_REG_GUEST_CS);
	ATF_CHECK_EQ(vmm_x86_startup_descriptor_vmreg(
	    VMM_X86_STARTUP_DESC_COUNT, &output), EINVAL);
	ATF_CHECK_EQ(output, VM_REG_GUEST_CS);
	ATF_CHECK_EQ(vmm_x86_startup_descriptor_vmreg(
	    VMM_X86_STARTUP_DESC_CS, NULL), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, register_mapping_is_complete);
	ATF_TP_ADD_TC(tp, descriptor_mapping_is_complete);
	ATF_TP_ADD_TC(tp, rejection_preserves_output);
	return (atf_no_error());
}
