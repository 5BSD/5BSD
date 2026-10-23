/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include "../../../sys/x86/include/specialreg.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/amd64/vmm/amd/nested_svm_cpuid.h"
#include "../../../sys/amd64/vmm/amd/nested_svm_compose.h"
#include "../../../sys/amd64/vmm/amd/nested_svm_policy.c"
#include "../../../sys/amd64/vmm/amd/nested_svm_msr.c"
#include "../../../sys/amd64/vmm/amd/nested_svm_aux.c"
#include "../../../sys/amd64/vmm/amd/nested_svm_l2_msr.c"
#include "../../../sys/amd64/vmm/amd/nested_svm_npt.c"
#include "../../../sys/amd64/vmm/amd/nested_svm_bitmap.c"
#include "../../../sys/amd64/vmm/amd/nested_svm_exit_policy.c"
#include "../../../sys/amd64/vmm/amd/nested_svm_operand.c"
#include "../../../sys/amd64/vmm/amd/nested_svm_reflect.c"

static struct svm_nested_vmcb12_view valid_vmcb12(void);

ATF_TC_WITHOUT_HEAD(l2_cr8_unmasked_policy);
ATF_TC_BODY(l2_cr8_unmasked_policy, tc)
{
	uint8_t reg;

	ATF_CHECK_EQ(svm_nested_cr8_intercept_mask(true), 0);
	ATF_CHECK_EQ(svm_nested_cr8_intercept_mask(false),
	    BIT(8) | BIT(24));
	ATF_CHECK(svm_nested_cr8_operand(5, false, &reg));
	ATF_CHECK_EQ(reg, 5);
	ATF_CHECK(svm_nested_cr8_operand(BIT(63) | 15, true, &reg));
	ATF_CHECK_EQ(reg, 15);
	ATF_CHECK(!svm_nested_cr8_operand(BIT(63) | 1, false, &reg));
	ATF_CHECK(!svm_nested_cr8_operand(1, true, &reg));
	ATF_CHECK(!svm_nested_cr8_operand(BIT(12) | 1, false, &reg));
	ATF_CHECK(!svm_nested_cr8_operand(0, false, NULL));
}

ATF_TC_WITHOUT_HEAD(l0_interrupt_window_not_inherited_by_l2);
ATF_TC_BODY(l0_interrupt_window_not_inherited_by_l2, tc)
{
	uint32_t l0, l1, composed;

	l0 = VMCB_INTCPT_VINTR | VMCB_INTCPT_IRET |
	    VMCB_INTCPT_PUSHF | VMCB_INTCPT_POPF | VMCB_INTCPT_IO;
	l1 = VMCB_INTCPT_VINTR;
	composed = svm_nested_l0_intercepts_for_l2(VMCB_CTRL1_INTCPT,
	    l0) | l1;
	ATF_CHECK_EQ(composed, VMCB_INTCPT_VINTR | VMCB_INTCPT_IO);
	ATF_CHECK_EQ(svm_nested_l0_intercepts_for_l2(VMCB_CTRL2_INTCPT,
	    l0), l0);
	ATF_CHECK_EQ(svm_nested_l0_intercepts_for_l2(VMCB_CTRL1_INTCPT,
	    VMCB_INTCPT_IRET), 0);
	ATF_CHECK_EQ(svm_nested_l0_intercepts_for_l2(VMCB_EXC_INTCPT,
	    BIT(1) | BIT(3) | BIT(18)), BIT(1) | BIT(3) | BIT(18));
	ATF_CHECK_EQ(svm_nested_l0_intercepts_for_l2(VMCB_EXC_INTCPT,
	    BIT(1)), BIT(1)); /* L0 tracing must survive VMCB02 composition. */
	ATF_CHECK_EQ(svm_nested_l0_intercepts_for_l2(VMCB_EXC_INTCPT,
	    UINT32_MAX), SVM_NESTED_L0_EXCEPTION_MASK);
	ATF_CHECK(svm_nested_l0_intercepts_supported(VMCB_CTRL1_INTCPT,
	    SVM_NESTED_L0_CTRL1_HANDLED | SVM_NESTED_L0_CTRL1_LOCAL));
	ATF_CHECK(svm_nested_l0_intercepts_supported(VMCB_CTRL2_INTCPT,
	    SVM_NESTED_L0_CTRL2_HANDLED));
	ATF_CHECK(svm_nested_l0_intercepts_supported(VMCB_CR_INTCPT,
	    SVM_NESTED_L0_CR_HANDLED));
	ATF_CHECK(!svm_nested_l0_intercepts_supported(VMCB_CR_INTCPT,
	    BIT(0)));
	ATF_CHECK(!svm_nested_l0_intercepts_supported(VMCB_CTRL1_INTCPT,
	    VMCB_INTCPT_RDTSC));
	ATF_CHECK(!svm_nested_l0_intercepts_supported(VMCB_CTRL2_INTCPT,
	    VMCB_INTCPT_XSETBV));
	ATF_CHECK(!svm_nested_l0_intercepts_supported(VMCB_DR_INTCPT,
	    BIT(0)));
	for (uint8_t vector = 0; vector < 32; vector++) {
		uint64_t eventinj;

		if ((SVM_NESTED_L0_EXCEPTION_MASK & BIT(vector)) == 0 ||
		    vector == 3 || vector == 18)
			continue;
		ATF_REQUIRE_EQ(svm_nested_l2_fault_injection(vector, 0,
		    0, 0, &eventinj), 0);
		ATF_CHECK_EQ(eventinj & 0xff, vector);
	}
}

ATF_TC_WITHOUT_HEAD(l0_debug_exit_ownership);
ATF_TC_BODY(l0_debug_exit_ownership, tc)
{
	uint32_t exceptions, controls;

	(void)tc;
	exceptions = BIT(1);
	controls = VMCB_INTCPT_PUSHF | VMCB_INTCPT_POPF;
	ATF_CHECK_EQ(svm_nested_l0_debug_exit(VMCB_EXIT_DB, exceptions,
	    controls, true, true), SVM_NESTED_L0_DEBUG_STEP);
	ATF_CHECK_EQ(svm_nested_l0_debug_exit(VMCB_EXIT_DB, exceptions,
	    controls, true, false), SVM_NESTED_L0_DEBUG_NONE);
	ATF_CHECK_EQ(svm_nested_l0_debug_exit(VMCB_EXIT_DB, exceptions,
	    controls, false, true), SVM_NESTED_L0_DEBUG_NONE);
	ATF_CHECK_EQ(svm_nested_l0_debug_exit(VMCB_EXIT_PUSHF, exceptions,
	    controls, true, false), SVM_NESTED_L0_DEBUG_PUSHF);
	ATF_CHECK_EQ(svm_nested_l0_debug_exit(VMCB_EXIT_POPF, exceptions,
	    controls, true, false), SVM_NESTED_L0_DEBUG_POPF);
	ATF_CHECK_EQ(svm_nested_l0_debug_exit(VMCB_EXIT_POPF, exceptions,
	    controls, false, false), SVM_NESTED_L0_DEBUG_NONE);
}

ATF_TC_WITHOUT_HEAD(l2_l0_exit_ownership);
ATF_TC_BODY(l2_l0_exit_ownership, tc)
{

	(void)tc;
	ATF_CHECK_EQ(svm_nested_l2_l0_exit_action(VMCB_EXIT_INTR),
	    SVM_NESTED_L2_RESUME);
	ATF_CHECK_EQ(svm_nested_l2_l0_exit_action(VMCB_EXIT_NMI),
	    SVM_NESTED_L2_RESUME);
	ATF_CHECK_EQ(svm_nested_l2_l0_exit_action(VMCB_EXIT_SMI),
	    SVM_NESTED_L2_REPORT_L0);
	ATF_CHECK_EQ(svm_nested_l2_l0_exit_action(VMCB_EXIT_INIT),
	    SVM_NESTED_L2_REPORT_L0);
	ATF_CHECK_EQ(svm_nested_l2_l0_exit_action(VMCB_EXIT_FERR_FREEZE),
	    SVM_NESTED_L2_REPORT_L0);
	ATF_CHECK_EQ(svm_nested_l2_l0_exit_action(VMCB_EXIT_MC),
	    SVM_NESTED_L2_MACHINE_CHECK);
	ATF_CHECK_EQ(svm_nested_l2_l0_exit_action(VMCB_EXIT_INVALID),
	    SVM_NESTED_L2_FAIL_L0);
	ATF_CHECK_EQ(svm_nested_l2_l0_exit_action(VMCB_EXIT_SHUTDOWN),
	    SVM_NESTED_L2_ROUTE);
	ATF_CHECK_EQ(svm_nested_l2_l0_exit_action(VMCB_EXIT_CPUID),
	    SVM_NESTED_L2_ROUTE);
	ATF_CHECK_EQ(svm_nested_l2_l0_exit_action(VMCB_EXIT_NPF),
	    SVM_NESTED_L2_ROUTE);
	{
		uint64_t info1, info2;

		info1 = UINT64_MAX;
		info2 = UINT64_MAX;
		svm_nested_l2_l0_exit_info(VMCB_EXIT_INIT, &info1, &info2);
		ATF_CHECK_EQ(info1, 0U);
		ATF_CHECK_EQ(info2, 0U);
		info1 = UINT64_MAX;
		info2 = UINT64_MAX;
		svm_nested_l2_l0_exit_info(VMCB_EXIT_FERR_FREEZE,
		    &info1, &info2);
		ATF_CHECK_EQ(info1, 0U);
		ATF_CHECK_EQ(info2, 0U);

		/* Preserve SMI source bits, never report undefined I/O state. */
		info1 = UINT64_MAX & ~(UINT64_C(1) << 33);
		info2 = UINT64_MAX;
		svm_nested_l2_l0_exit_info(VMCB_EXIT_SMI, &info1, &info2);
		ATF_CHECK_EQ(info1, 3U);
		ATF_CHECK_EQ(info2, 0U);
		info1 = (UINT64_C(1) << 33) | 1;
		info2 = 0x1234;
		svm_nested_l2_l0_exit_info(VMCB_EXIT_SMI, &info1, &info2);
		ATF_CHECK_EQ(info1, (UINT64_C(1) << 33) | 1);
		ATF_CHECK_EQ(info2, 0x1234U);
		info1 = (UINT64_C(1) << 42) |
		    (UINT64_C(0x7ffff) << 13) | (UINT64_C(0xff) << 2) |
		    (UINT64_C(1) << 33) | (UINT64_C(0x12) << 48) | 3;
		info2 = 0x5678;
		svm_nested_l2_l0_exit_info(VMCB_EXIT_SMI, &info1, &info2);
		ATF_CHECK_EQ(info1, (UINT64_C(1) << 33) |
		    (UINT64_C(0x12) << 48) | 3);
		ATF_CHECK_EQ(info2, 0x5678U);
	}
}

ATF_TC_WITHOUT_HEAD(l2_cpuid_hides_svm);
ATF_TC_BODY(l2_cpuid_hides_svm, tc)
{
	uint32_t regs[4], before[4];

	regs[0] = 1;
	regs[1] = 2;
	regs[2] = (1U << 2) | (1U << 3);
	regs[3] = 4;
	svm_nested_l2_cpuid_filter(0x80000001, regs);
	ATF_CHECK_EQ(regs[0], 1);
	ATF_CHECK_EQ(regs[1], 2);
	ATF_CHECK_EQ(regs[2], 1U << 3);
	ATF_CHECK_EQ(regs[3], 4);
	memcpy(before, regs, sizeof(before));
	svm_nested_l2_cpuid_filter(0x80000008, regs);
	ATF_CHECK_EQ(memcmp(regs, before, sizeof(regs)), 0);
	svm_nested_l2_cpuid_filter(0x8000000a, regs);
	ATF_CHECK_EQ(regs[0] | regs[1] | regs[2] | regs[3], 0);
	regs[0] = 1;
	regs[1] = 2;
	regs[2] = (1U << 31) | (1U << 5);
	regs[3] = 4;
	svm_nested_l2_cpuid_filter(1, regs);
	ATF_CHECK_EQ(regs[2], 1U << 5);
	svm_nested_l2_cpuid_filter(0x40000001, regs);
	ATF_CHECK_EQ(regs[0] | regs[1] | regs[2] | regs[3], 0);
}

ATF_TC_WITHOUT_HEAD(l2_vmcb_msr_accesses);
ATF_TC_BODY(l2_vmcb_msr_accesses, tc)
{
	static const struct {
		uint32_t msr;
		uint32_t offset;
	} fields[] = {
		{ MSR_TSC, VMCB_OFF_TSC_OFFSET },
		{ MSR_EFER, VMCB_OFF_STATE(0xd0) },
		{ MSR_FSBASE, VMCB_OFF_STATE(0x48) },
		{ MSR_GSBASE, VMCB_OFF_STATE(0x58) },
		{ MSR_KGSBASE, VMCB_OFF_KERNELGBASE },
		{ MSR_STAR, VMCB_OFF_STAR },
		{ MSR_LSTAR, VMCB_OFF_LSTAR },
		{ MSR_CSTAR, VMCB_OFF_CSTAR },
		{ MSR_SF_MASK, VMCB_OFF_SFMASK },
		{ MSR_SYSENTER_CS_MSR, VMCB_OFF_SYSENTER_CS },
		{ MSR_SYSENTER_ESP_MSR, VMCB_OFF_SYSENTER_ESP },
		{ MSR_SYSENTER_EIP_MSR, VMCB_OFF_SYSENTER_EIP },
		{ MSR_PAT, VMCB_OFF_GUEST_PAT },
	};
	uint8_t vmcb02[4096], vmcb12[4096], portable[4096];
	uint8_t restored[4096];
	uint64_t value, saved, expected;

	memset(vmcb02, 0, sizeof(vmcb02));
	for (size_t i = 0; i < nitems(fields); i++) {
		saved = 0x1234567800000000ULL | fields[i].msr;
		if (fields[i].msr == MSR_EFER)
			saved |= EFER_SVM;
		memcpy(vmcb02 + fields[i].offset, &saved, sizeof(saved));
		value = 0;
		ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(vmcb02,
		    fields[i].msr, 0, &value));
		expected = saved;
		if (fields[i].msr == MSR_EFER)
			expected &= ~EFER_SVM;
		if (fields[i].msr == MSR_SF_MASK ||
		    fields[i].msr == MSR_SYSENTER_CS_MSR)
			expected = (uint32_t)expected;
		ATF_CHECK_EQ(value, expected);
		if (fields[i].msr == MSR_TSC) {
			ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(vmcb02,
			    MSR_TSC, 0x1234, &value));
			ATF_CHECK_EQ(value, saved + 0x1234);
		}
	}
	value = 0xfeedface;
	ATF_CHECK(!svm_nested_l2_vmcb_msr_read(vmcb02, MSR_VM_CR,
	    0, &value));
	ATF_CHECK_EQ(value, 0xfeedface);
	ATF_CHECK(!svm_nested_l2_vmcb_msr_read(NULL, MSR_STAR,
	    0, &value));
	ATF_CHECK(!svm_nested_l2_vmcb_msr_read(vmcb02, MSR_STAR,
	    0, NULL));
	ATF_REQUIRE_EQ(svm_nested_l2_vmcb_msr_write(vmcb02, MSR_STAR,
	    0xfedcba9876543210ULL), SVM_NESTED_L2_MSR_APPLIED);
	ATF_REQUIRE_EQ(svm_nested_l2_vmcb_msr_write(vmcb02, MSR_LSTAR,
	    0xffff800000000000ULL), SVM_NESTED_L2_MSR_APPLIED);
	ATF_REQUIRE_EQ(svm_nested_l2_vmcb_msr_write(vmcb02, MSR_CSTAR,
	    0x12345678ULL), SVM_NESTED_L2_MSR_APPLIED);
	ATF_CHECK_EQ(svm_nested_l2_vmcb_msr_write(vmcb02, MSR_LSTAR,
	    0x0000800000000000ULL), SVM_NESTED_L2_MSR_GP);
	ATF_CHECK_EQ(svm_nested_l2_vmcb_msr_write(vmcb02, MSR_CSTAR,
	    0x123456789abcdef0ULL), SVM_NESTED_L2_MSR_GP);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(vmcb02, MSR_LSTAR,
	    0, &value));
	ATF_CHECK_EQ(value, 0xffff800000000000ULL);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(vmcb02, MSR_CSTAR,
	    0, &value));
	ATF_CHECK_EQ(value, 0x12345678ULL);
	ATF_REQUIRE_EQ(svm_nested_l2_vmcb_msr_write(vmcb02, MSR_SF_MASK,
	    0xffffffff12345678ULL), SVM_NESTED_L2_MSR_APPLIED);
	ATF_REQUIRE_EQ(svm_nested_l2_vmcb_msr_write(vmcb02,
	    MSR_SYSENTER_CS_MSR, 0xffffffff00000033ULL),
	    SVM_NESTED_L2_MSR_APPLIED);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(vmcb02,
	    MSR_SYSENTER_CS_MSR, 0, &value));
	ATF_CHECK_EQ(value, 0x33);
	ATF_REQUIRE_EQ(svm_nested_l2_vmcb_msr_write(vmcb02,
	    MSR_SYSENTER_ESP_MSR, 0xffff800000001000ULL),
	    SVM_NESTED_L2_MSR_APPLIED);
	ATF_REQUIRE_EQ(svm_nested_l2_vmcb_msr_write(vmcb02,
	    MSR_SYSENTER_EIP_MSR, 0xffff800000002000ULL),
	    SVM_NESTED_L2_MSR_APPLIED);
	ATF_REQUIRE_EQ(svm_nested_l2_vmcb_msr_write(vmcb02, MSR_PAT,
	    0x0007040600070406ULL), SVM_NESTED_L2_MSR_APPLIED);
	ATF_CHECK_EQ(svm_nested_l2_vmcb_msr_write(vmcb02, MSR_PAT,
	    0x0007040600070402ULL), SVM_NESTED_L2_MSR_GP);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(vmcb02, MSR_PAT,
	    0, &value));
	ATF_CHECK_EQ(value, 0x0007040600070406ULL);
	saved = 0;
	memcpy(vmcb02 + VMCB_OFF_STATE(0x158), &saved, sizeof(saved));
	ATF_REQUIRE_EQ(svm_nested_l2_efer_write(vmcb02,
	    EFER_SCE | EFER_LME | EFER_NXE, true, false, false),
	    SVM_NESTED_L2_MSR_APPLIED);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(vmcb02, MSR_EFER,
	    0, &value));
	ATF_CHECK_EQ(value, EFER_SCE | EFER_LME | EFER_NXE);
	ATF_CHECK_EQ(svm_nested_l2_efer_write(vmcb02,
	    EFER_SCE | EFER_LME | EFER_NXE | EFER_SVM, true, false,
	    false), SVM_NESTED_L2_MSR_GP);
	ATF_CHECK_EQ(svm_nested_l2_efer_write(vmcb02,
	    EFER_SCE | EFER_LME | EFER_NXE, false, false, false),
	    SVM_NESTED_L2_MSR_GP);
	saved = CR0_PG;
	memcpy(vmcb02 + VMCB_OFF_STATE(0x158), &saved, sizeof(saved));
	ATF_CHECK_EQ(svm_nested_l2_efer_write(vmcb02,
	    EFER_SCE | EFER_NXE, true, false, false),
	    SVM_NESTED_L2_MSR_GP);
	ATF_REQUIRE_EQ(svm_nested_l2_efer_write(vmcb02,
	    EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE, true, false, false),
	    SVM_NESTED_L2_MSR_APPLIED);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(vmcb02, MSR_EFER,
	    0, &value));
	ATF_CHECK_EQ(value, EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE);
	ATF_CHECK_EQ(svm_nested_l2_efer_write(NULL, 0, false, false,
	    false), SVM_NESTED_L2_MSR_UNSUPPORTED);
	ATF_CHECK_EQ(svm_nested_l2_vmcb_msr_write(NULL, MSR_STAR, 0),
	    SVM_NESTED_L2_MSR_UNSUPPORTED);
	ATF_REQUIRE_EQ(svm_nested_l2_vmcb_msr_write(vmcb02, MSR_FSBASE,
	    0xffff800000000000ULL), SVM_NESTED_L2_MSR_APPLIED);
	ATF_CHECK_EQ(svm_nested_l2_vmcb_msr_write(vmcb02, MSR_FSBASE,
	    0x0000800000000000ULL), SVM_NESTED_L2_MSR_GP);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(vmcb02, MSR_FSBASE,
	    0, &value));
	ATF_CHECK_EQ(value, 0xffff800000000000ULL);
	ATF_REQUIRE_EQ(svm_nested_l2_vmcb_msr_write(vmcb02, MSR_GSBASE,
	    0x1234), SVM_NESTED_L2_MSR_APPLIED);
	ATF_REQUIRE_EQ(svm_nested_l2_vmcb_msr_write(vmcb02, MSR_KGSBASE,
	    0xffff800000000000ULL), SVM_NESTED_L2_MSR_APPLIED);
	ATF_CHECK_EQ(svm_nested_l2_vmcb_msr_write(vmcb02, MSR_KGSBASE,
	    0x0000800000000000ULL), SVM_NESTED_L2_MSR_GP);
	memset(vmcb12, 0, sizeof(vmcb12));
	svm_nested_vmcb_checkpoint_copy(portable, vmcb12, vmcb02, false,
	    true);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(portable, MSR_STAR,
	    0, &value));
	ATF_CHECK_EQ(value, 0xfedcba9876543210ULL);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(portable, MSR_LSTAR,
	    0, &value));
	ATF_CHECK_EQ(value, 0xffff800000000000ULL);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(portable, MSR_CSTAR,
	    0, &value));
	ATF_CHECK_EQ(value, 0x12345678ULL);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(portable, MSR_SF_MASK,
	    0, &value));
	ATF_CHECK_EQ(value, 0x12345678ULL);
	memset(restored, 0, sizeof(restored));
	svm_nested_vmcb_aux_copy(restored, portable);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(restored, MSR_STAR,
	    0, &value));
	ATF_CHECK_EQ(value, 0xfedcba9876543210ULL);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(restored, MSR_SF_MASK,
	    0, &value));
	ATF_CHECK_EQ(value, 0x12345678ULL);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(restored, MSR_FSBASE,
	    0, &value));
	ATF_CHECK_EQ(value, 0xffff800000000000ULL);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(restored, MSR_GSBASE,
	    0, &value));
	ATF_CHECK_EQ(value, 0x1234);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(restored, MSR_KGSBASE,
	    0, &value));
	ATF_CHECK_EQ(value, 0xffff800000000000ULL);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(restored,
	    MSR_SYSENTER_CS_MSR, 0, &value));
	ATF_CHECK_EQ(value, 0x33);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(restored,
	    MSR_SYSENTER_ESP_MSR, 0, &value));
	ATF_CHECK_EQ(value, 0xffff800000001000ULL);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(restored,
	    MSR_SYSENTER_EIP_MSR, 0, &value));
	ATF_CHECK_EQ(value, 0xffff800000002000ULL);
	ATF_REQUIRE(svm_nested_l2_vmcb_msr_read(portable, MSR_PAT,
	    0, &value));
	ATF_CHECK_EQ(value, 0x0007040600070406ULL);
}

ATF_TC_WITHOUT_HEAD(l2_event_replay);
ATF_TC_BODY(l2_event_replay, tc)
{
	uint64_t event, next;

	next = 0x1234;
	ATF_REQUIRE_EQ(svm_nested_l2_event_replay(0, 0, &next), 0);
	ATF_CHECK_EQ(next, 0);
	event = VMCB_EVENTINJ_VALID |
	    ((uint64_t)VMCB_EVENTINJ_TYPE_EXCEPTION << 8) |
	    VMCB_EVENTINJ_EC_VALID | 13 | (0xbeefULL << 32);
	ATF_REQUIRE_EQ(svm_nested_l2_event_replay(0, event, &next), 0);
	ATF_CHECK_EQ(next, event);
	next = 0x1234;
	ATF_CHECK_EQ(svm_nested_l2_event_replay(event, event, &next),
	    EPROTO);
	ATF_CHECK_EQ(next, 0x1234);
	ATF_CHECK_EQ(svm_nested_l2_event_replay(0,
	    event | (1ULL << 12), &next), EPROTO);
	ATF_CHECK_EQ(next, 0x1234);
	ATF_CHECK_EQ(svm_nested_l2_event_replay(0, event, NULL), EINVAL);
	ATF_CHECK_EQ(next, 0x1234);
	/* L0 tracing must preserve the L2 fault vector and hardware error. */
	next = 0x1234;
	ATF_REQUIRE_EQ(svm_nested_l2_fault_injection(14, 0xbeef,
	    0, 0, &next), 0);
	ATF_CHECK_EQ(next, VMCB_EVENTINJ_VALID |
	    VMCB_EVENTINJ_EC_VALID |
	    ((uint64_t)VMCB_EVENTINJ_TYPE_EXCEPTION << 8) |
	    14 | (0xbeefULL << 32));
	ATF_REQUIRE_EQ(svm_nested_l2_fault_injection(6, 0xbeef,
	    0, 0, &next), 0);
	ATF_CHECK_EQ(next, VMCB_EVENTINJ_VALID |
	    ((uint64_t)VMCB_EVENTINJ_TYPE_EXCEPTION << 8) | 6);
	/* An L0 tracing intercept must return an unowned guest #DB to L2. */
	ATF_REQUIRE_EQ(svm_nested_l2_fault_injection(1, 0,
	    0, 0, &next), 0);
	ATF_CHECK_EQ(next, VMCB_EVENTINJ_VALID |
	    ((uint64_t)VMCB_EVENTINJ_TYPE_EXCEPTION << 8) | 1);
	/* AMD defines vector 4 injection as the post-INTO #OF trap. */
	ATF_REQUIRE_EQ(svm_nested_l2_fault_injection(4, 0,
	    0, 0, &next), 0);
	ATF_CHECK_EQ(next, VMCB_EVENTINJ_VALID |
	    ((uint64_t)VMCB_EVENTINJ_TYPE_EXCEPTION << 8) | 4);
	ATF_REQUIRE_EQ(svm_nested_l2_fault_injection(8, 0xbeef,
	    0, 0, &next), 0);
	ATF_CHECK_EQ(next, VMCB_EVENTINJ_VALID |
	    VMCB_EVENTINJ_EC_VALID |
	    ((uint64_t)VMCB_EVENTINJ_TYPE_EXCEPTION << 8) | 8);
	next = 0x1234;
	ATF_CHECK_EQ(svm_nested_l2_fault_injection(14, 0, event, 0,
	    &next), EAGAIN);
	ATF_CHECK_EQ(next, 0x1234);
	ATF_CHECK_EQ(svm_nested_l2_fault_injection(3, 0, 0, 0,
	    &next), EOPNOTSUPP);
	ATF_CHECK_EQ(next, 0x1234);
	ATF_CHECK_EQ(svm_nested_l2_fault_injection(14, 0, 0, 0,
	    NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(l2_async_event_selection);
ATF_TC_BODY(l2_async_event_selection, tc)
{
	struct svm_nested_pending_event event;
	uint64_t injection;

	event = (struct svm_nested_pending_event) {
		.l1_intercepts = VMCB_INTCPT_NMI | VMCB_INTCPT_INTR,
		.l1_rflags = 0x202,
		.l2_rflags = 0x202,
		.nmi_pending = true,
		.irq_pending = true,
	};
	injection = VMCB_EVENTINJ_VALID |
	    ((uint64_t)VMCB_EVENTINJ_TYPE_EXCEPTION << 8) | 13;
	ATF_CHECK_EQ(svm_nested_pending_event_exit(&event), VMCB_EXIT_NMI);
	event.nmi_blocked = true;
	ATF_CHECK_EQ(svm_nested_pending_event_exit(&event), VMCB_EXIT_INTR);
	event.nmi_blocked = false;
	event.nmi_pending = false;
	ATF_CHECK_EQ(svm_nested_pending_event_exit(&event), VMCB_EXIT_INTR);
	event.l2_rflags = 2;
	ATF_CHECK_EQ(svm_nested_pending_event_exit(&event), 0);
	event.l1_intr_masking = true;
	ATF_CHECK_EQ(svm_nested_pending_event_exit(&event), VMCB_EXIT_INTR);
	event.l1_rflags = 2;
	ATF_CHECK_EQ(svm_nested_pending_event_exit(&event), 0);
	event.nmi_pending = true;
	ATF_CHECK_EQ(svm_nested_pending_event_exit(&event), VMCB_EXIT_NMI);
	event.eventinj = injection;
	ATF_CHECK_EQ(svm_nested_pending_event_exit(&event), 0);
	event.eventinj = 0;
	event.exitintinfo = injection;
	ATF_CHECK_EQ(svm_nested_pending_event_exit(&event), 0);
	event.exitintinfo = 0;
	event.mask_hwintr = true;
	ATF_CHECK_EQ(svm_nested_pending_event_exit(&event), 0);
	event.mask_hwintr = false;
	/* An unintercepted NMI must not be overtaken by an IRQ exit. */
	event.l1_intercepts = VMCB_INTCPT_INTR;
	ATF_CHECK_EQ(svm_nested_pending_event_exit(&event), 0);
	event.nmi_pending = false;
	event.l1_intercepts = 0;
	ATF_CHECK_EQ(svm_nested_pending_event_exit(&event), 0);
	ATF_CHECK_EQ(svm_nested_pending_event_exit(NULL), 0);
}

ATF_TC_WITHOUT_HEAD(l2_synthetic_exception_ownership);
ATF_TC_BODY(l2_synthetic_exception_ownership, tc)
{
	struct svm_nested_synthetic_exception result, before;
	uint64_t pending;

	memset(&result, 0xa5, sizeof(result));
	ATF_REQUIRE_EQ(svm_nested_synthetic_exception_prepare(1U << 13,
	    0, 0, 13, true, 0, &result), 0);
	ATF_CHECK_EQ(result.action, SVM_NESTED_SYNTHETIC_REFLECT);
	ATF_CHECK_EQ(result.exitcode, 0x40 + 13);
	ATF_CHECK_EQ(result.exitinfo1, 0);
	ATF_CHECK_EQ(result.eventinj, 0);
	ATF_REQUIRE_EQ(svm_nested_synthetic_exception_prepare(1U << 6,
	    0, 0, 6, false, 0, &result), 0);
	ATF_CHECK_EQ(result.action, SVM_NESTED_SYNTHETIC_REFLECT);
	ATF_CHECK_EQ(result.exitcode, 0x40 + 6);
	ATF_REQUIRE_EQ(svm_nested_synthetic_exception_prepare(0,
	    0, 0, 13, true, 0, &result), 0);
	ATF_CHECK_EQ(result.action, SVM_NESTED_SYNTHETIC_INJECT);
	ATF_CHECK_EQ(result.eventinj, VMCB_EVENTINJ_VALID |
	    VMCB_EVENTINJ_EC_VALID |
	    ((uint64_t)VMCB_EVENTINJ_TYPE_EXCEPTION << 8) | 13);
	ATF_REQUIRE_EQ(svm_nested_synthetic_exception_prepare(0,
	    0, 0, 6, false, 0, &result), 0);
	ATF_CHECK_EQ(result.action, SVM_NESTED_SYNTHETIC_INJECT);
	ATF_CHECK_EQ(result.eventinj, VMCB_EVENTINJ_VALID |
	    ((uint64_t)VMCB_EVENTINJ_TYPE_EXCEPTION << 8) | 6);
	/* AMD INIT redirection becomes #SX with error code 1. */
	ATF_REQUIRE_EQ(svm_nested_synthetic_exception_prepare(1U << 30,
	    0, 0, 30, true, 1, &result), 0);
	ATF_CHECK_EQ(result.action, SVM_NESTED_SYNTHETIC_REFLECT);
	ATF_CHECK_EQ(result.exitcode, 0x40 + 30);
	ATF_CHECK_EQ(result.exitinfo1, 1);
	ATF_REQUIRE_EQ(svm_nested_synthetic_exception_prepare(0,
	    0, 0, 30, true, 1, &result), 0);
	ATF_CHECK_EQ(result.action, SVM_NESTED_SYNTHETIC_INJECT);
	ATF_CHECK_EQ(result.eventinj, VMCB_EVENTINJ_VALID |
	    VMCB_EVENTINJ_EC_VALID | (1ULL << 32) |
	    ((uint64_t)VMCB_EVENTINJ_TYPE_EXCEPTION << 8) | 30);
	pending = VMCB_EVENTINJ_VALID |
	    ((uint64_t)VMCB_EVENTINJ_TYPE_EXCEPTION << 8) | 14;
	ATF_REQUIRE_EQ(svm_nested_synthetic_exception_prepare(1U << 13,
	    0, pending, 13, true, 0, &result), 0);
	ATF_CHECK_EQ(result.action, SVM_NESTED_SYNTHETIC_REPLAY);
	ATF_CHECK_EQ(result.eventinj | result.exitcode | result.exitinfo1, 0);
	before = result;
	ATF_CHECK_EQ(svm_nested_synthetic_exception_prepare(0,
	    0, 0, 6, true, 0, &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&result, &before, sizeof(result)), 0);
	ATF_CHECK_EQ(svm_nested_synthetic_exception_prepare(0,
	    0, 0, 13, false, 0, &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&result, &before, sizeof(result)), 0);
	ATF_CHECK_EQ(svm_nested_synthetic_exception_prepare(0,
	    0, 0, 13, true, 0, NULL), EINVAL);
	ATF_CHECK_EQ(svm_nested_synthetic_exception_prepare(0,
	    0, 0, 30, true, 0, &result), EINVAL);
}

ATF_TC_WITHOUT_HEAD(l2_portio_decode);
ATF_TC_BODY(l2_portio_decode, tc)
{
	struct svm_nested_portio io;
	const uint64_t info = (0x3f8ULL << 16) | (4ULL << 4) | 1;

	memset(&io, 0, sizeof(io));
	ATF_REQUIRE_EQ(svm_nested_portio_decode(info, 0x1000, 0x1002,
	    &io), 0);
	ATF_CHECK(io.in);
	ATF_CHECK_EQ(io.bytes, 4);
	ATF_CHECK_EQ(io.port, 0x3f8);
	ATF_CHECK_EQ(io.next_rip, 0x1002);
	ATF_CHECK_EQ(svm_nested_portio_decode(info, 0x1000, 0x1000,
	    &io), EINVAL);
	ATF_CHECK_EQ(svm_nested_portio_decode(info, 0x1000, 0x1010,
	    &io), EINVAL);
	ATF_CHECK_EQ(svm_nested_portio_decode(info | (1ULL << 2),
	    0x1000, 0x1002, &io), EINVAL);
	ATF_REQUIRE_EQ(svm_nested_portio_decode(info | (1ULL << 3),
	    0x1000, 0x1002, &io), 0);
	ATF_CHECK_EQ(io.port, 0x3f8);
	ATF_CHECK_EQ(io.bytes, 4);
	ATF_CHECK_EQ(svm_nested_portio_decode(info & ~(7ULL << 4),
	    0x1000, 0x1002, &io), EINVAL);
	ATF_CHECK_EQ(svm_nested_portio_decode(info, 0x1000, 0x1002,
	    NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(svm_instruction_address_size);
ATF_TC_BODY(svm_instruction_address_size, tc)
{
	const uint8_t vmrun[] = { 0x0f, 0x01, 0xd8 };
	const uint8_t vmload32[] = { 0x67, 0x0f, 0x01, 0xda };
	const uint8_t vmsave16[] = { 0x67, 0x0f, 0x01, 0xdb };
	const uint8_t prefixed[] = { 0x66, 0x67, 0x67, 0x0f, 0x01, 0xd8 };
	const uint8_t changed[] = { 0x0f, 0x01, 0xd9 };
	uint64_t gpa;

	ATF_REQUIRE_EQ(svm_nested_operand_gpa(vmrun, sizeof(vmrun), 64,
	    0xd8, 0x123456789abcdef0ULL, &gpa), 0);
	ATF_CHECK_EQ(gpa, 0x123456789abcdef0ULL);
	ATF_REQUIRE_EQ(svm_nested_operand_gpa(vmload32, sizeof(vmload32),
	    64, 0xda, 0x123456789abcdef0ULL, &gpa), 0);
	ATF_CHECK_EQ(gpa, 0x9abcdef0ULL);
	ATF_REQUIRE_EQ(svm_nested_operand_gpa(vmrun, sizeof(vmrun), 32,
	    0xd8, 0x123456789abcdef0ULL, &gpa), 0);
	ATF_CHECK_EQ(gpa, 0x9abcdef0ULL);
	ATF_REQUIRE_EQ(svm_nested_operand_gpa(vmsave16, sizeof(vmsave16),
	    32, 0xdb, 0x123456789abcdef0ULL, &gpa), 0);
	ATF_CHECK_EQ(gpa, 0xdef0ULL);
	ATF_REQUIRE_EQ(svm_nested_operand_gpa(vmsave16, sizeof(vmsave16),
	    16, 0xdb, 0x123456789abcdef0ULL, &gpa), 0);
	ATF_CHECK_EQ(gpa, 0x9abcdef0ULL);
	ATF_REQUIRE_EQ(svm_nested_operand_gpa(prefixed, sizeof(prefixed),
	    64, 0xd8, 0x123456789abcdef0ULL, &gpa), 0);
	ATF_CHECK_EQ(gpa, 0x9abcdef0ULL);
	ATF_CHECK_EQ(svm_nested_operand_gpa(changed, sizeof(changed), 64,
	    0xd8, 0, &gpa), EPROTO);
}

ATF_TC_WITHOUT_HEAD(vmcb12_exit_writeback_scope);
ATF_TC_BODY(vmcb12_exit_writeback_scope, tc)
{
	uint8_t vmcb12[4096], vmcb02[4096];

	memset(vmcb12, 0xa5, sizeof(vmcb12));
	memset(vmcb02, 0x5a, sizeof(vmcb02));
	svm_nested_vmcb_exit_copy(vmcb12, vmcb02, false, true);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_EXIT_REASON], 0x5a);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_CTRL(0xc8)], 0x5a);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_CTRL(0xd1)], 0x5a);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_STATE(0x00)], 0x5a);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_STATE(0x148)], 0x5a);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_STATE(0x240)], 0x5a);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_GUEST_PAT], 0x5a);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_DBGCTL], 0xa5);
	/* L1's VMLOAD auxiliary state and hardware pointer fields survive. */
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_STATE(0x40)], 0xa5);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_STATE(0x70)], 0xa5);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_STAR], 0xa5);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_IO_PERM], 0xa5);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_MSR_PERM], 0xa5);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_NPT_BASE], 0xa5);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_ASID], 0xa5);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_CTRL(0x61)], 0xa4);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_CTRL(0x68)], 0xa4);
	svm_nested_vmcb_exit_copy(vmcb12, vmcb02, true, false);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_DBGCTL], 0x5a);
	vmcb12[VMCB_OFF_GUEST_PAT] = 0xa5;
	svm_nested_vmcb_exit_copy(vmcb12, vmcb02, false, false);
	ATF_CHECK_EQ(vmcb12[VMCB_OFF_GUEST_PAT], 0xa5);
}

ATF_TC_WITHOUT_HEAD(vmcb12_checkpoint_portability);
ATF_TC_BODY(vmcb12_checkpoint_portability, tc)
{
	uint8_t vmcb12[4096], vmcb02[4096], portable[4096];

	memset(vmcb12, 0xa5, sizeof(vmcb12));
	memset(vmcb02, 0x5a, sizeof(vmcb02));
	memset(portable, 0, sizeof(portable));
	svm_nested_vmcb_checkpoint_copy(portable, vmcb12, vmcb02, false,
	    false);
	/* Hardware pointers and ASID come only from L1's guest VMCB. */
	ATF_CHECK_EQ(portable[VMCB_OFF_IO_PERM], 0xa5);
	ATF_CHECK_EQ(portable[VMCB_OFF_MSR_PERM], 0xa5);
	ATF_CHECK_EQ(portable[VMCB_OFF_NPT_BASE], 0xa5);
	ATF_CHECK_EQ(portable[VMCB_OFF_ASID], 0xa5);
	/* L2's guest registers, VMLOAD MSRs, and LBR state survive. */
	ATF_CHECK_EQ(portable[VMCB_OFF_STATE(0x148)], 0x5a);
	ATF_CHECK_EQ(portable[VMCB_OFF_STATE(0x40)], 0x5a);
	ATF_CHECK_EQ(portable[VMCB_OFF_STAR], 0x5a);
	ATF_CHECK_EQ(portable[VMCB_OFF_DBGCTL], 0x5a);
	ATF_CHECK_EQ(portable[VMCB_OFF_GUEST_PAT], 0xa5);
}

ATF_TC_WITHOUT_HEAD(vmcb12_shutdown_writeback_scope);
ATF_TC_BODY(vmcb12_shutdown_writeback_scope, tc)
{
	uint8_t vmcb12[4096], expected[4096];
	uint64_t code;

	memset(vmcb12, 0xa5, sizeof(vmcb12));
	memset(expected, 0xa5, sizeof(expected));
	code = VMCB_EXIT_SHUTDOWN;
	memcpy(expected + VMCB_OFF_EXIT_REASON, &code, sizeof(code));
	memset(expected + VMCB_OFF_EXITINFO1, 0, 0x18);
	memset(expected + VMCB_OFF_CTRL(0xa8), 0, 8);
	memset(expected + VMCB_OFF_CTRL(0xc8), 0, 0x18);
	svm_nested_vmcb_shutdown_copy(vmcb12);
	ATF_CHECK_EQ(memcmp(vmcb12, expected, sizeof(vmcb12)), 0);
}

struct bitmap_test_memory {
	uint8_t iopm[3 * 4096];
	uint8_t msrpm[2 * 4096];
};

static int
bitmap_test_read8(void *arg, uint64_t gpa, uint8_t *value)
{
	struct bitmap_test_memory *memory;

	memory = arg;
	if (gpa >= 0x10000 && gpa < 0x10000 + sizeof(memory->iopm)) {
		*value = memory->iopm[gpa - 0x10000];
		return (0);
	}
	if (gpa >= 0x20000 && gpa < 0x20000 + sizeof(memory->msrpm)) {
		*value = memory->msrpm[gpa - 0x20000];
		return (0);
	}
	return (EFAULT);
}

ATF_TC_WITHOUT_HEAD(l1_bitmap_exit_ownership);
ATF_TC_BODY(l1_bitmap_exit_ownership, tc)
{
	struct bitmap_test_memory memory;
	struct svm_nested_bitmap_reader reader;
	bool intercept;

	memset(&memory, 0, sizeof(memory));
	reader.read8 = bitmap_test_read8;
	reader.arg = &memory;
	ATF_REQUIRE_EQ(svm_nested_iopm_intercepts(&reader, 0x10000,
	    0xfffe, 4, &intercept), 0);
	ATF_CHECK(!intercept);
	/* A four-byte access spans beyond port 65535 into the third page. */
	memory.iopm[8192] = 1;
	ATF_REQUIRE_EQ(svm_nested_iopm_intercepts(&reader, 0x10000,
	    0xfffe, 4, &intercept), 0);
	ATF_CHECK(intercept);
	memory.iopm[8192] = 0;
	memory.iopm[0xffff / 8] = 1U << 7;
	ATF_REQUIRE_EQ(svm_nested_iopm_intercepts(&reader, 0x10000,
	    0xfffe, 2, &intercept), 0);
	ATF_CHECK(intercept);
	ATF_CHECK_EQ(svm_nested_iopm_intercepts(&reader, 0x10000,
	    0, 3, &intercept), EINVAL);
	ATF_CHECK_EQ(svm_nested_iopm_intercepts(&reader, 0x30000,
	    0, 1, &intercept), EFAULT);

	ATF_REQUIRE_EQ(svm_nested_msrpm_intercepts(&reader, 0x20000,
	    0xc0010003U, false, &intercept), 0);
	ATF_CHECK(!intercept);
	memory.msrpm[4096] = 1U << 6;
	ATF_REQUIRE_EQ(svm_nested_msrpm_intercepts(&reader, 0x20000,
	    0xc0010003U, false, &intercept), 0);
	ATF_CHECK(intercept);
	ATF_REQUIRE_EQ(svm_nested_msrpm_intercepts(&reader, 0x20000,
	    0xc0010003U, true, &intercept), 0);
	ATF_CHECK(!intercept);
	ATF_REQUIRE_EQ(svm_nested_msrpm_intercepts(&reader, 0x20000,
	    0xc0020000U, false, &intercept), 0);
	ATF_CHECK(intercept);
	ATF_CHECK_EQ(svm_nested_msrpm_intercepts(&reader, 0x30000,
	    0xc0010003U, false, &intercept), EFAULT);
}

ATF_TC_WITHOUT_HEAD(l1_exit_intercept_precedence);
ATF_TC_BODY(l1_exit_intercept_precedence, tc)
{
	struct bitmap_test_memory memory;
	struct svm_nested_bitmap_reader reader;
	struct svm_nested_vmcb12_view view;
	bool intercept;

	memset(&memory, 0, sizeof(memory));
	reader.read8 = bitmap_test_read8;
	reader.arg = &memory;
	view = valid_vmcb12();
	view.iopm_gpa = 0x10000;
	view.msrpm_gpa = 0x20000;
	/* L0's forced IO/MSR intercepts alone must never reflect to L1. */
	ATF_REQUIRE_EQ(svm_nested_exit_intercepted(&view, &reader,
	    VMCB_EXIT_IO, (uint64_t)0x3f8 << 16 | 1U << 4,
	    0, &intercept), 0);
	ATF_CHECK(!intercept);
	view.intercept[VMCB_CTRL1_INTCPT] =
	    VMCB_INTCPT_IO | VMCB_INTCPT_MSR | VMCB_INTCPT_CPUID;
	ATF_REQUIRE_EQ(svm_nested_exit_intercepted(&view, &reader,
	    VMCB_EXIT_IO, (uint64_t)0x3f8 << 16 | 1U << 4,
	    0, &intercept), 0);
	ATF_CHECK(!intercept);
	memory.iopm[0x3f8 >> 3] = 1;
	view.iopm_gpa |= 0x5a5; /* Hardware ignores the low address bits. */
	ATF_REQUIRE_EQ(svm_nested_exit_intercepted(&view, &reader,
	    VMCB_EXIT_IO, (uint64_t)0x3f8 << 16 | 1U << 4,
	    0, &intercept), 0);
	ATF_CHECK(intercept);
	ATF_REQUIRE_EQ(svm_nested_exit_intercepted(&view, &reader,
	    VMCB_EXIT_MSR, 0, 0xc0010003U, &intercept), 0);
	ATF_CHECK(!intercept);
	memory.msrpm[4096] = 1U << 7;
	view.msrpm_gpa |= 0x789;
	ATF_REQUIRE_EQ(svm_nested_exit_intercepted(&view, &reader,
	    VMCB_EXIT_MSR, 1, 0xc0010003U, &intercept), 0);
	ATF_CHECK(intercept);
	ATF_REQUIRE_EQ(svm_nested_exit_intercepted(&view, &reader,
	    VMCB_EXIT_CPUID, 0, 0, &intercept), 0);
	ATF_CHECK(intercept);
	ATF_REQUIRE_EQ(svm_nested_exit_intercepted(&view, &reader,
	    VMCB_EXIT_NPF, 0, 0, &intercept), 0);
	ATF_CHECK(!intercept);
}

static struct svm_nested_vmcb12_view
valid_vmcb12(void)
{
	struct svm_nested_vmcb12_view view = {
		.vmcb_gpa = 0x1000,
		.hsave_gpa = 0x2000,
		.iopm_gpa = 0x3000,
		.msrpm_gpa = 0x6000,
		.npt_root_gpa = 0x8000,
		.efer = EFER_SVM,
		.asid = 1,
	};

	view.intercept[VMCB_CTRL2_INTCPT] = VMCB_INTCPT_VMRUN;
	return (view);
}

ATF_TC_WITHOUT_HEAD(physical_range_boundaries);
ATF_TC_BODY(physical_range_boundaries, tc)
{
	const uint64_t limit = 1ULL << 32;

	ATF_CHECK(svm_nested_guest_physical_range_valid(0, 1, 32));
	ATF_CHECK(svm_nested_guest_physical_range_valid(limit - 1, 1, 32));
	ATF_CHECK(!svm_nested_guest_physical_range_valid(limit, 1, 32));
	ATF_CHECK(!svm_nested_guest_physical_range_valid(limit - 1, 2, 32));
	ATF_CHECK(!svm_nested_guest_physical_range_valid(0, 0, 32));
	ATF_CHECK(!svm_nested_guest_physical_range_valid(0, 1, 31));
	ATF_CHECK(svm_nested_guest_physical_range_valid(0, 1, 53));
	ATF_CHECK(!svm_nested_guest_physical_range_valid(0, 1, 64));
	ATF_CHECK_EQ(svm_nested_physical_width(52), 47);
	ATF_CHECK_EQ(svm_nested_physical_width(36), 36);
	ATF_CHECK(svm_nested_guest_physical_range_valid(
	    (1ULL << 47) - SVM_NESTED_PAGE_SIZE, SVM_NESTED_PAGE_SIZE,
	    svm_nested_physical_width(52)));
	ATF_CHECK(!svm_nested_guest_physical_range_valid(1ULL << 47, 1,
	    svm_nested_physical_width(52)));
}

ATF_TC_WITHOUT_HEAD(vmcb12_control_admission);
ATF_TC_BODY(vmcb12_control_admission, tc)
{
	struct svm_nested_vmcb12_view view, before;

	view = valid_vmcb12();
	before = view;
	ATF_REQUIRE(svm_nested_vmcb12_view_valid(&view, 48, false));
	ATF_CHECK_EQ(memcmp(&view, &before, sizeof(view)), 0);
	view.intercept[VMCB_CTRL2_INTCPT] = 0;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view = valid_vmcb12();
	view.asid = 0;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view = valid_vmcb12();
	view.v_tpr = 15;
	ATF_CHECK(svm_nested_vmcb12_view_valid(&view, 48, false));
	view.v_tpr = 16;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view = valid_vmcb12();
	view.vnmi_controls = 1;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view = valid_vmcb12();
	view.tlb_ctrl = 3;
	ATF_CHECK(svm_nested_vmcb12_view_valid(&view, 48, false));
	view.tlb_ctrl = 7;
	ATF_CHECK(svm_nested_vmcb12_view_valid(&view, 48, false));
	view.tlb_ctrl = 2;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view = valid_vmcb12();
	view.iopm_gpa = (1ULL << 32) - 2 * SVM_NESTED_PAGE_SIZE;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 32, false));
	view.iopm_gpa = (1ULL << 32) - 3 * SVM_NESTED_PAGE_SIZE;
	ATF_CHECK(svm_nested_vmcb12_view_valid(&view, 32, false));
	view = valid_vmcb12();
	view.iopm_gpa |= 0xfff;
	view.msrpm_gpa |= 0xfff;
	ATF_CHECK(svm_nested_vmcb12_view_valid(&view, 48, false));
	view.msrpm_gpa = 1ULL << 48;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view = valid_vmcb12();
	view.npt_control = 1;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	ATF_CHECK(svm_nested_vmcb12_view_valid(&view, 48, true));
	view.npt_root_gpa++;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, true));
	view = valid_vmcb12();
	view.npt_control = 2;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, true));
	ATF_CHECK(!svm_nested_vmcb12_view_valid(NULL, 48, true));
}

ATF_TC_WITHOUT_HEAD(vmcb12_state_admission);
ATF_TC_BODY(vmcb12_state_admission, tc)
{
	struct svm_nested_vmcb12_view view;

	view = valid_vmcb12();
	view.efer = 0;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view = valid_vmcb12();
	view.efer |= 1ULL << 9;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view = valid_vmcb12();
	view.efer |= 1ULL << 22;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view = valid_vmcb12();
	view.cr3 = 1ULL << 48;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view = valid_vmcb12();
	view.dr6 = 1ULL << 32;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view = valid_vmcb12();
	view.dr7 = 1ULL << 32;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view = valid_vmcb12();
	view.g_pat = 0x0007040600070406ULL;
	ATF_CHECK(svm_nested_vmcb12_view_valid(&view, 48, false));
	view.g_pat = 0x0007040600070402ULL;
	ATF_CHECK(svm_nested_vmcb12_view_valid(&view, 48, false));
	view.npt_control = 1;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, true));
	view = valid_vmcb12();
	view.cr0 = CR0_NW;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view.cr0 |= CR0_CD;
	ATF_CHECK(svm_nested_vmcb12_view_valid(&view, 48, false));
	view = valid_vmcb12();
	view.efer |= EFER_LME;
	view.cr0 = CR0_PG;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view.cr0 |= CR0_PE;
	view.cr4 = CR4_PAE;
	ATF_CHECK(svm_nested_vmcb12_view_valid(&view, 48, false));
	view.efer |= EFER_LMA;
	ATF_CHECK(svm_nested_vmcb12_view_valid(&view, 48, false));
	view.cr0 &= ~CR0_PG;
	ATF_CHECK(svm_nested_vmcb12_view_valid(&view, 48, false));
	view.cr0 |= CR0_PG;
	view.cs_attrib = VMCB_CS_ATTRIB_L | VMCB_CS_ATTRIB_D;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view = valid_vmcb12();
	view.cr0 = CR0_PG;
	/* SVM VMRUN permits PG=1, PE=0 outside long mode. */
	ATF_CHECK(svm_nested_vmcb12_view_valid(&view, 48, false));
	view = valid_vmcb12();
	view.efer |= EFER_LMA;
	/* Hardware does not cross-check LMA with LME and PG on VMRUN. */
	ATF_CHECK(svm_nested_vmcb12_view_valid(&view, 48, false));
	view = valid_vmcb12();
	view.eventinj = VMCB_EVENTINJ_VALID | (1ULL << 8);
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view.eventinj = VMCB_EVENTINJ_VALID |
	    (VMCB_EVENTINJ_TYPE_EXCEPTION << 8) | 13;
	ATF_CHECK(svm_nested_vmcb12_view_valid(&view, 48, false));
	view.eventinj |= 1ULL << 12;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view.eventinj = VMCB_EVENTINJ_VALID |
	    (VMCB_EVENTINJ_TYPE_EXCEPTION << 8) | 15;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view.eventinj = VMCB_EVENTINJ_VALID |
	    (VMCB_EVENTINJ_TYPE_EXCEPTION << 8) | 32;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	/* #CP and #VC require CET and SEV-ES, neither exposed to L1. */
	view.eventinj = VMCB_EVENTINJ_VALID |
	    (VMCB_EVENTINJ_TYPE_EXCEPTION << 8) | 21;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view.eventinj = VMCB_EVENTINJ_VALID |
	    (VMCB_EVENTINJ_TYPE_EXCEPTION << 8) | 29;
	ATF_CHECK(!svm_nested_vmcb12_view_valid(&view, 48, false));
	view.eventinj = VMCB_EVENTINJ_VALID |
	    (VMCB_EVENTINJ_TYPE_EXCEPTION << 8) | 30;
	ATF_CHECK(svm_nested_vmcb12_view_valid(&view, 48, false));
	/* Injection fields are ignored unless the valid bit is set. */
	view.eventinj = 1ULL << 12;
	ATF_CHECK(svm_nested_vmcb12_view_valid(&view, 48, false));
}

ATF_TC_WITHOUT_HEAD(virtual_svm_msr_state);
ATF_TC_BODY(virtual_svm_msr_state, tc)
{
	struct svm_nested_msr_state state, before;

	svm_nested_msr_state_init(&state);
	ATF_REQUIRE(svm_nested_msr_state_valid(&state, 48));
	ATF_CHECK_EQ(svm_nested_msr_efer_read(&state, EFER_SVM), 0);
	ATF_CHECK(svm_nested_msr_efer_write_allowed(&state, 0));
	ATF_CHECK(!svm_nested_msr_efer_write_allowed(&state, EFER_SVM));
	svm_nested_msr_efer_import(&state, EFER_SVM);
	ATF_CHECK(!state.svme);
	ATF_CHECK(!svm_nested_msr_hsave_write(&state, 0x1000, 48));
	ATF_CHECK_EQ(svm_nested_msr_exposure_set(&state, 2, false),
	    EINVAL);
	ATF_CHECK_EQ(svm_nested_msr_exposure_set(&state, 1, true), EBUSY);
	ATF_REQUIRE_EQ(svm_nested_msr_exposure_set(&state, 1, false), 0);
	ATF_CHECK(state.exposed);
	ATF_CHECK_EQ(svm_nested_msr_exposure_set(&state, 1, true), 0);
	ATF_CHECK(svm_nested_msr_efer_write_allowed(&state, EFER_SVM));
	svm_nested_msr_efer_import(&state, EFER_SVM);
	ATF_CHECK(state.svme);
	ATF_CHECK_EQ(svm_nested_msr_exposure_set(&state, 0, false), EBUSY);
	ATF_CHECK_EQ(svm_nested_msr_efer_read(&state, 0), EFER_SVM);
	before = state;
	ATF_CHECK(!svm_nested_msr_hsave_write(&state, 0x1234, 48));
	ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
	ATF_CHECK(!svm_nested_msr_hsave_write(&state, 1ULL << 48, 48));
	ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
	ATF_CHECK(svm_nested_msr_hsave_write(&state, 0x3000, 48));
	ATF_CHECK(svm_nested_msr_state_valid(&state, 48));
	before = state;
	ATF_CHECK(!svm_nested_msr_vmcr_write(&state, VM_CR_SVMDIS));
	ATF_CHECK_EQ(memcmp(&state, &before, sizeof(state)), 0);
	svm_nested_msr_efer_import(&state, 0);
	ATF_CHECK(svm_nested_msr_vmcr_write(&state, VM_CR_SVMDIS));
	ATF_CHECK(!svm_nested_msr_efer_write_allowed(&state, EFER_SVM));
	ATF_CHECK(svm_nested_msr_state_valid(&state, 48));
	ATF_CHECK(svm_nested_msr_vmcr_write(&state, VM_CR_LOCK));
	ATF_CHECK_EQ(state.vm_cr, VM_CR_LOCK);
	ATF_CHECK(svm_nested_msr_vmcr_write(&state, 0));
	ATF_CHECK_EQ(state.vm_cr, VM_CR_LOCK);
	ATF_CHECK(svm_nested_msr_vmcr_write(&state, VM_CR_R_INIT));
	ATF_CHECK_EQ(state.vm_cr, VM_CR_LOCK | VM_CR_R_INIT);
	ATF_CHECK(svm_nested_msr_state_valid(&state, 48));
	ATF_CHECK(svm_nested_msr_vmcr_write(&state, 0));
	ATF_CHECK_EQ(state.vm_cr, VM_CR_LOCK);
	ATF_CHECK(!svm_nested_msr_vmcr_write(&state, 1ULL << 5));
	ATF_CHECK_EQ(state.vm_cr, VM_CR_LOCK);
	svm_nested_msr_efer_import(&state, EFER_SVM);
	ATF_CHECK(!svm_nested_msr_vmcr_write(&state,
	    VM_CR_LOCK | VM_CR_SVMDIS));
	ATF_CHECK_EQ(state.vm_cr, VM_CR_LOCK);
	ATF_CHECK_EQ(svm_nested_msr_exposure_set(&state, 0, false), EBUSY);
	state.exposed = false;
	ATF_CHECK(!svm_nested_msr_state_valid(&state, 48));
	svm_nested_msr_state_init(&state);
	ATF_REQUIRE_EQ(svm_nested_msr_exposure_set(&state, 1, false), 0);
	ATF_REQUIRE_EQ(svm_nested_msr_exposure_set(&state, 0, false), 0);
	ATF_CHECK(svm_nested_msr_state_valid(&state, 48));
}

ATF_TC_WITHOUT_HEAD(virtual_svm_init_signal);
ATF_TC_BODY(virtual_svm_init_signal, tc)
{
	struct svm_nested_msr_state state;

	/* Unlocked SVMDIS clears, while the programmed HSAVE address survives. */
	svm_nested_msr_state_init(&state);
	ATF_REQUIRE_EQ(svm_nested_msr_exposure_set(&state, 1, false), 0);
	ATF_REQUIRE(svm_nested_msr_hsave_write(&state, 0x3000, 48));
	ATF_REQUIRE(svm_nested_msr_vmcr_write(&state, VM_CR_SVMDIS));
	ATF_REQUIRE(svm_nested_msr_vmcr_write(&state,
	    VM_CR_R_INIT | VM_CR_SVMDIS));
	svm_nested_msr_init_signal(&state);
	ATF_CHECK(state.exposed);
	ATF_CHECK(!state.svme);
	ATF_CHECK_EQ(state.hsave_gpa, 0x3000);
	ATF_CHECK_EQ(state.vm_cr, 0);
	ATF_CHECK(svm_nested_msr_efer_write_allowed(&state, EFER_SVM));

	/* A locked SVMDIS survives INIT. */
	ATF_REQUIRE(svm_nested_msr_vmcr_write(&state,
	    VM_CR_R_INIT | VM_CR_LOCK | VM_CR_SVMDIS));
	svm_nested_msr_init_signal(&state);
	ATF_CHECK(!state.svme);
	ATF_CHECK_EQ(state.vm_cr, VM_CR_LOCK | VM_CR_SVMDIS);
	ATF_CHECK_EQ(state.hsave_gpa, 0x3000);
	ATF_CHECK(!svm_nested_msr_efer_write_allowed(&state, EFER_SVM));
	ATF_CHECK(svm_nested_msr_state_valid(&state, 48));

	/* With SVM enabled, INIT clears SVME but preserves a locked VM_CR. */
	svm_nested_msr_state_init(&state);
	ATF_REQUIRE_EQ(svm_nested_msr_exposure_set(&state, 1, false), 0);
	ATF_REQUIRE(svm_nested_msr_vmcr_write(&state, VM_CR_LOCK));
	svm_nested_msr_efer_import(&state, EFER_SVM);
	ATF_REQUIRE(state.svme);
	svm_nested_msr_init_signal(&state);
	ATF_CHECK(!state.svme);
	ATF_CHECK_EQ(state.vm_cr, VM_CR_LOCK);
	ATF_CHECK(svm_nested_msr_state_valid(&state, 48));
}

ATF_TC_WITHOUT_HEAD(vmload_vmsave_aux_fields);
ATF_TC_BODY(vmload_vmsave_aux_fields, tc)
{
	uint8_t source[4096], destination[4096], expected[4096];
	size_t i;

	for (i = 0; i < sizeof(source); i++)
		source[i] = (uint8_t)(i * 37 + 13);
	memset(destination, 0xa5, sizeof(destination));
	memset(expected, 0xa5, sizeof(expected));
	/* Independent byte ranges from APM 15.5.2 and VMCB appendix B. */
	memcpy(expected + 0x440, source + 0x440, 0x20); /* FS, GS */
	memcpy(expected + 0x470, source + 0x470, 0x10); /* LDTR */
	memcpy(expected + 0x490, source + 0x490, 0x10); /* TR */
	memcpy(expected + 0x600, source + 0x600, 0x40); /* syscall MSRs */
	svm_nested_vmcb_aux_copy(destination, source);
	ATF_CHECK_EQ(memcmp(destination, expected, sizeof(expected)), 0);
}

struct npt_test_memory {
	uint64_t page[4][512];
};

static int
npt_test_read64(void *arg, uint64_t gpa, uint64_t *value)
{
	struct npt_test_memory *memory;
	uint64_t page, index;

	memory = arg;
	if (gpa < 0x1000 || gpa >= 0x5000 || (gpa & 7) != 0)
		return (EFAULT);
	page = (gpa >> 12) - 1;
	index = (gpa & 0xfff) >> 3;
	*value = memory->page[page][index];
	return (0);
}

static int
npt_test_compare_exchange64(void *arg, uint64_t gpa, uint64_t expected,
    uint64_t desired, uint64_t *observed)
{
	struct npt_test_memory *memory;
	uint64_t page, index;

	memory = arg;
	if (gpa < 0x1000 || gpa >= 0x5000 || (gpa & 7) != 0 ||
	    observed == NULL)
		return (EFAULT);
	page = (gpa >> 12) - 1;
	index = (gpa & 0xfff) >> 3;
	*observed = memory->page[page][index];
	if (*observed == expected)
		memory->page[page][index] = desired;
	return (0);
}

ATF_TC_WITHOUT_HEAD(npt12_translation_and_faults);
ATF_TC_BODY(npt12_translation_and_faults, tc)
{
	struct npt_test_memory memory;
	struct svm_nested_npt_memory ops;
	struct svm_nested_npt_walk walk;
	struct svm_nested_npt_result result;
	uint64_t gpa, info1, pd_index, pdpt_index, pt_index;
	uint8_t access;

	memset(&memory, 0, sizeof(memory));
	gpa = 0x123456789ULL;
	pdpt_index = (gpa >> 30) & 0x1ff;
	pd_index = (gpa >> 21) & 0x1ff;
	pt_index = (gpa >> 12) & 0x1ff;
	memory.page[0][(gpa >> 39) & 0x1ff] = 0x2000 | 7;
	memory.page[1][pdpt_index] = 0x3000 | 7;
	memory.page[2][pd_index] = 0x4000 | 7;
	memory.page[3][pt_index] = 0x8000 | 7;
	ops.read64 = npt_test_read64;
	ops.compare_exchange64 = npt_test_compare_exchange64;
	ops.arg = &memory;
	memset(&walk, 0, sizeof(walk));
	walk.root_gpa = 0x1000;
	walk.l2_gpa = gpa;
	walk.physical_width = 48;
	walk.access = SVM_NESTED_NPT_READ;
	ATF_REQUIRE_EQ(svm_nested_npt_walk(&walk, &ops, &result), 0);
	ATF_CHECK_EQ(result.outcome, SVM_NESTED_NPT_TRANSLATED);
	ATF_CHECK_EQ(result.l1_gpa, 0x8789);
	ATF_CHECK_EQ(result.count, 4);
	ATF_CHECK_EQ(result.page_shift, 12);
	ATF_CHECK_EQ(result.ad_desired[0], memory.page[0][0] | (1ULL << 5));
	ATF_CHECK_EQ(result.ad_desired[3],
	    memory.page[3][pt_index] | (1ULL << 5));
	/* AMD checks a guest page-table read as an NPT user data write. */
	ATF_REQUIRE_EQ(svm_nested_npt_software_access(true, false,
	    false, false, &access, &info1), 0);
	ATF_CHECK_EQ(access, SVM_NESTED_NPT_WRITE);
	ATF_CHECK_EQ(info1, NPF_GPT | NPF_U | NPF_W);
	memory.page[3][pt_index] &= ~NPT_RW;
	walk.access = access;
	ATF_REQUIRE_EQ(svm_nested_npt_walk(&walk, &ops, &result), 0);
	ATF_CHECK_EQ(result.outcome, SVM_NESTED_NPT_VIOLATION);
	ATF_REQUIRE_EQ(svm_nested_npt_reflect_info1(&result, info1,
	    &info1), 0);
	ATF_CHECK_EQ(info1, NPF_P | NPF_GPT | NPF_U | NPF_W);
	memory.page[3][pt_index] |= NPT_RW;
	ATF_REQUIRE_EQ(svm_nested_npt_software_access(false, false,
	    false, true, &access, &info1), 0);
	ATF_CHECK_EQ(access, SVM_NESTED_NPT_EXECUTE);
	ATF_CHECK_EQ(info1, NPF_GPA | NPF_ID);
	ATF_REQUIRE_EQ(svm_nested_npt_software_access(false, true,
	    true, false, &access, &info1), 0);
	ATF_CHECK_EQ(access, SVM_NESTED_NPT_WRITE);
	ATF_CHECK_EQ(info1, NPF_GPA | NPF_U | NPF_W);
	walk.access = SVM_NESTED_NPT_WRITE;
	ATF_REQUIRE_EQ(svm_nested_npt_walk(&walk, &ops, &result), 0);
	ATF_CHECK_EQ(result.ad_desired[0], memory.page[0][0] | (1ULL << 5));
	ATF_CHECK_EQ(result.ad_desired[3],
	    memory.page[3][pt_index] | (1ULL << 5) | (1ULL << 6));
	ATF_REQUIRE_EQ(svm_nested_npt_commit_ad(&result, &ops), 0);
	ATF_CHECK_EQ(memory.page[0][0], result.ad_desired[0]);
	ATF_CHECK_EQ(memory.page[3][pt_index], result.ad_desired[3]);
	/* Even a no-op A/D update must notice that L1 changed the leaf. */
	ATF_REQUIRE_EQ(svm_nested_npt_walk(&walk, &ops, &result), 0);
	memory.page[3][pt_index] ^= 1ULL << 1;
	ATF_CHECK_EQ(svm_nested_npt_commit_ad(&result, &ops), EAGAIN);
	memory.page[3][pt_index] ^= 1ULL << 1;
	/* A concurrent L1 edit requires a new walk before mapping NPT02. */
	memory.page[0][0] = 0x2000 | 7;
	memory.page[3][pt_index] = 0x8000 | 7;
	ATF_REQUIRE_EQ(svm_nested_npt_walk(&walk, &ops, &result), 0);
	memory.page[0][0] = 0x3000 | 7;
	ATF_CHECK_EQ(svm_nested_npt_commit_ad(&result, &ops), EAGAIN);
	ATF_CHECK_EQ(memory.page[3][pt_index], 0x8000 | 7);
	memory.page[0][0] = 0x2000 | 7;

	memory.page[3][pt_index] = 0x8000 | 5;
	ATF_REQUIRE_EQ(svm_nested_npt_walk(&walk, &ops, &result), 0);
	ATF_CHECK_EQ(result.outcome, SVM_NESTED_NPT_VIOLATION);
	ATF_REQUIRE_EQ(svm_nested_npt_reflect_info1(&result,
	    NPF_W | NPF_U | NPF_GPA | NPF_RSV, &info1), 0);
	ATF_CHECK_EQ(info1, NPF_P | NPF_W | NPF_U | NPF_GPA);
	memory.page[3][pt_index] = 0x8000 | 7 | (1ULL << 63);
	walk.access = SVM_NESTED_NPT_EXECUTE;
	ATF_REQUIRE_EQ(svm_nested_npt_walk(&walk, &ops, &result), 0);
	ATF_CHECK_EQ(result.outcome, SVM_NESTED_NPT_VIOLATION);
	memory.page[3][pt_index] = 0x8000 | 3;
	walk.access = SVM_NESTED_NPT_READ;
	ATF_REQUIRE_EQ(svm_nested_npt_walk(&walk, &ops, &result), 0);
	ATF_CHECK_EQ(result.outcome, SVM_NESTED_NPT_VIOLATION);
	memory.page[3][pt_index] = 0;
	ATF_REQUIRE_EQ(svm_nested_npt_walk(&walk, &ops, &result), 0);
	ATF_CHECK_EQ(result.outcome, SVM_NESTED_NPT_VIOLATION);
	ATF_REQUIRE_EQ(svm_nested_npt_reflect_info1(&result,
	    NPF_W | NPF_ID | NPF_P, &info1), 0);
	ATF_CHECK_EQ(info1, NPF_W | NPF_ID);
	memory.page[3][pt_index] = (1ULL << 48) | 7;
	ATF_REQUIRE_EQ(svm_nested_npt_walk(&walk, &ops, &result), 0);
	ATF_CHECK_EQ(result.outcome, SVM_NESTED_NPT_RESERVED);
	ATF_REQUIRE_EQ(svm_nested_npt_reflect_info1(&result,
	    NPF_U | NPF_GPT, &info1), 0);
	ATF_CHECK_EQ(info1, NPF_P | NPF_U | NPF_RSV | NPF_GPT);

	memory.page[2][pd_index] = 0x200000 | 0x87;
	ATF_REQUIRE_EQ(svm_nested_npt_walk(&walk, &ops, &result), 0);
	ATF_CHECK_EQ(result.outcome, SVM_NESTED_NPT_TRANSLATED);
	ATF_CHECK_EQ(result.l1_gpa, 0x200000 + (gpa & 0x1fffff));
	ATF_CHECK_EQ(result.page_shift, 21);
	ATF_CHECK_EQ(result.count, 3);
	memory.page[2][pd_index] |= 1ULL << 13;
	ATF_REQUIRE_EQ(svm_nested_npt_walk(&walk, &ops, &result), 0);
	ATF_CHECK_EQ(result.outcome, SVM_NESTED_NPT_RESERVED);
	/* A reserved huge-page bit wins over a simultaneous write denial. */
	memory.page[2][pd_index] &= ~NPT_RW;
	walk.access = SVM_NESTED_NPT_WRITE;
	ATF_REQUIRE_EQ(svm_nested_npt_walk(&walk, &ops, &result), 0);
	ATF_CHECK_EQ(result.outcome, SVM_NESTED_NPT_RESERVED);
	walk.access = SVM_NESTED_NPT_READ;

	memory.page[1][pdpt_index] = 0x40000000 | 0x87;
	walk.allow_1g_pages = true;
	ATF_REQUIRE_EQ(svm_nested_npt_walk(&walk, &ops, &result), 0);
	ATF_CHECK_EQ(result.outcome, SVM_NESTED_NPT_TRANSLATED);
	ATF_CHECK_EQ(result.l1_gpa, 0x40000000 + (gpa & 0x3fffffff));
	ATF_CHECK_EQ(result.page_shift, 30);
	ATF_CHECK_EQ(svm_nested_npt_reflect_info1(&result, 0, &info1),
	    EINVAL);
	walk.allow_1g_pages = false;
	ATF_REQUIRE_EQ(svm_nested_npt_walk(&walk, &ops, &result), 0);
	ATF_CHECK_EQ(result.outcome, SVM_NESTED_NPT_RESERVED);
	/* A four-level walk must not alias bit 48 onto address zero. */
	walk.physical_width = 52;
	walk.l2_gpa = gpa | (1ULL << 48);
	ATF_CHECK_EQ(svm_nested_npt_walk(&walk, &ops, &result), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, l2_cr8_unmasked_policy);
	ATF_TP_ADD_TC(tp, l0_interrupt_window_not_inherited_by_l2);
	ATF_TP_ADD_TC(tp, l0_debug_exit_ownership);
	ATF_TP_ADD_TC(tp, l2_l0_exit_ownership);
	ATF_TP_ADD_TC(tp, physical_range_boundaries);
	ATF_TP_ADD_TC(tp, l2_cpuid_hides_svm);
	ATF_TP_ADD_TC(tp, l2_vmcb_msr_accesses);
	ATF_TP_ADD_TC(tp, l2_event_replay);
	ATF_TP_ADD_TC(tp, l2_async_event_selection);
	ATF_TP_ADD_TC(tp, l2_synthetic_exception_ownership);
	ATF_TP_ADD_TC(tp, l2_portio_decode);
	ATF_TP_ADD_TC(tp, vmcb12_control_admission);
	ATF_TP_ADD_TC(tp, vmcb12_state_admission);
	ATF_TP_ADD_TC(tp, virtual_svm_msr_state);
	ATF_TP_ADD_TC(tp, virtual_svm_init_signal);
	ATF_TP_ADD_TC(tp, vmload_vmsave_aux_fields);
	ATF_TP_ADD_TC(tp, npt12_translation_and_faults);
	ATF_TP_ADD_TC(tp, l1_bitmap_exit_ownership);
	ATF_TP_ADD_TC(tp, l1_exit_intercept_precedence);
	ATF_TP_ADD_TC(tp, svm_instruction_address_size);
	ATF_TP_ADD_TC(tp, vmcb12_exit_writeback_scope);
	ATF_TP_ADD_TC(tp, vmcb12_shutdown_writeback_scope);
	ATF_TP_ADD_TC(tp, vmcb12_checkpoint_portability);
	return (atf_no_error());
}
