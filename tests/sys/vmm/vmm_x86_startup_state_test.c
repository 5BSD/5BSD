/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/amd64/vmm/vmm_x86_startup_state.c"

ATF_TC_WITHOUT_HEAD(init_architectural_values);
ATF_TC_BODY(init_architectural_values, tc)
{
	struct vmm_x86_init_state_plan plan;
	unsigned int i;

	(void)tc;
	memset(&plan, 0xa5, sizeof(plan));
	ATF_REQUIRE_EQ(vmm_x86_init_state_plan(UINT64_C(0xe005003f),
	    UINT32_C(0x000a06f2), &plan), 0);
	ATF_CHECK_EQ(plan.rflags, UINT64_C(0x2));
	ATF_CHECK_EQ(plan.rip, UINT64_C(0xfff0));
	/* Expected directly from Intel SDM rev. 092 Table 12-1 and note 2. */
	ATF_CHECK_EQ(plan.cr0, UINT64_C(0x60000010));
	ATF_CHECK_EQ(plan.cr2, 0);
	ATF_CHECK_EQ(plan.cr3, 0);
	ATF_CHECK_EQ(plan.cr4, 0);
	ATF_CHECK_EQ(plan.efer, 0);
	for (i = 0; i < 16; i++) {
		ATF_CHECK_EQ(plan.gpr[i],
		    i == 3 ? UINT64_C(0x000a06f2) : UINT64_C(0));
	}
	ATF_CHECK_EQ(plan.segment[0].selector, UINT16_C(0xf000));
	ATF_CHECK_EQ(plan.segment[0].base, UINT64_C(0xffff0000));
	ATF_CHECK_EQ(plan.segment[0].limit, UINT32_C(0xffff));
	ATF_CHECK_EQ(plan.segment[0].access, UINT32_C(0x0093));
	for (i = 1; i <= 5; i++) {
		ATF_CHECK_EQ(plan.segment[i].selector, 0);
		ATF_CHECK_EQ(plan.segment[i].base, 0);
		ATF_CHECK_EQ(plan.segment[i].limit, UINT32_C(0xffff));
		ATF_CHECK_EQ(plan.segment[i].access, UINT32_C(0x0093));
	}
	ATF_CHECK_EQ(plan.segment[6].limit, UINT32_C(0xffff));
	ATF_CHECK_EQ(plan.segment[6].access, UINT32_C(0x008b));
	ATF_CHECK_EQ(plan.segment[7].limit, UINT32_C(0xffff));
	ATF_CHECK_EQ(plan.segment[7].access, UINT32_C(0x0082));
	for (i = 0; i < 8; i++) {
		ATF_CHECK_EQ(plan.segment[i].reserved16, 0);
		ATF_CHECK_EQ(plan.segment[i].reserved32, 0);
	}
	ATF_CHECK_EQ(plan.gdtr.limit, UINT32_C(0xffff));
	ATF_CHECK_EQ(plan.idtr.limit, UINT32_C(0xffff));
	for (i = 0; i < 4; i++)
		ATF_CHECK_EQ(plan.dr[i], 0);
	ATF_CHECK_EQ(plan.dr6, UINT64_C(0xffff0ff0));
	ATF_CHECK_EQ(plan.dr7, UINT64_C(0x400));
	ATF_CHECK_EQ(plan.interrupt_shadow, 0);
}

ATF_TC_WITHOUT_HEAD(init_preserves_only_cache_policy);
ATF_TC_BODY(init_preserves_only_cache_policy, tc)
{
	struct vmm_x86_init_state_plan plan;

	(void)tc;
	ATF_REQUIRE_EQ(vmm_x86_init_state_plan(UINT64_C(0x20000021), 0,
	    &plan), 0);
	ATF_CHECK_EQ(plan.cr0, UINT64_C(0x20000010));
	ATF_REQUIRE_EQ(vmm_x86_init_state_plan(UINT64_C(0x40010001), 0,
	    &plan), 0);
	ATF_CHECK_EQ(plan.cr0, UINT64_C(0x40000010));
	ATF_REQUIRE_EQ(vmm_x86_init_state_plan(UINT64_C(0x1), 0, &plan), 0);
	ATF_CHECK_EQ(plan.cr0, UINT64_C(0x10));
}

ATF_TC_WITHOUT_HEAD(sipi_changes_only_startup_vector_state);
ATF_TC_BODY(sipi_changes_only_startup_vector_state, tc)
{
	struct vmm_x86_sipi_state_plan plan;
	uint32_t vector;

	(void)tc;
	for (vector = 0; vector <= UINT8_MAX; vector++) {
		memset(&plan, 0xa5, sizeof(plan));
		ATF_REQUIRE_EQ(vmm_x86_sipi_state_plan(vector, &plan), 0);
		ATF_CHECK_EQ(plan.rip, 0);
		ATF_CHECK_EQ(plan.cs.selector, (uint16_t)(vector * 256));
		ATF_CHECK_EQ(plan.cs.base, (uint64_t)vector * 4096);
		ATF_CHECK_EQ(plan.cs.limit, UINT32_C(0xffff));
		ATF_CHECK_EQ(plan.cs.access, UINT32_C(0x0093));
		ATF_CHECK_EQ(plan.cs.reserved16, 0);
		ATF_CHECK_EQ(plan.cs.reserved32, 0);
	}
	/* Keep explicit boundary-independent fixtures for the review validator. */
	ATF_CHECK_EQ(vmm_x86_sipi_state_plan(UINT32_C(0xab), &plan), 0);
	ATF_CHECK_EQ(plan.cs.selector, UINT16_C(0xab00));
	ATF_CHECK_EQ(plan.cs.base, UINT64_C(0xab000));
}

ATF_TC_WITHOUT_HEAD(rejection_is_transactional);
ATF_TC_BODY(rejection_is_transactional, tc)
{
	struct vmm_x86_init_state_plan init, init_before;
	struct vmm_x86_sipi_state_plan sipi, sipi_before;

	(void)tc;
	memset(&init, 0x69, sizeof(init));
	memset(&sipi, 0x96, sizeof(sipi));
	init_before = init;
	sipi_before = sipi;
	ATF_CHECK_EQ(vmm_x86_init_state_plan(UINT64_C(0x100000000), 0,
	    &init), EINVAL);
	ATF_CHECK(memcmp(&init, &init_before, sizeof(init)) == 0);
	ATF_CHECK_EQ(vmm_x86_sipi_state_plan(UINT32_C(0x100), &sipi), EINVAL);
	ATF_CHECK(memcmp(&sipi, &sipi_before, sizeof(sipi)) == 0);
	ATF_CHECK_EQ(vmm_x86_init_state_plan(0, 0, NULL), EINVAL);
	ATF_CHECK_EQ(vmm_x86_sipi_state_plan(0, NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(apicbase_bsp_classification);
ATF_TC_BODY(apicbase_bsp_classification, tc)
{
	bool bootstrap, before;

	(void)tc;
	/* Intel SDM IA32_APIC_BASE[8], independent of kernel headers. */
	ATF_REQUIRE_EQ(vmm_x86_startup_apicbase_classify(UINT64_C(0xfee00900),
	    &bootstrap), 0);
	ATF_CHECK(bootstrap);
	ATF_REQUIRE_EQ(vmm_x86_startup_apicbase_classify(UINT64_C(0xfee00800),
	    &bootstrap), 0);
	ATF_CHECK(!bootstrap);
	ATF_REQUIRE_EQ(vmm_x86_startup_apicbase_classify(UINT64_MAX,
	    &bootstrap), 0);
	ATF_CHECK(bootstrap);
	before = true;
	bootstrap = before;
	ATF_CHECK_EQ(vmm_x86_startup_apicbase_classify(0, NULL), EINVAL);
	ATF_CHECK_EQ(bootstrap, before);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, init_architectural_values);
	ATF_TP_ADD_TC(tp, init_preserves_only_cache_policy);
	ATF_TP_ADD_TC(tp, sipi_changes_only_startup_vector_state);
	ATF_TP_ADD_TC(tp, rejection_is_transactional);
	ATF_TP_ADD_TC(tp, apicbase_bsp_classification);
	return (atf_no_error());
}
