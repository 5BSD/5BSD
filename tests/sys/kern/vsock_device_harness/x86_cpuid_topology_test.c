/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>

#include <machine/specialreg.h>
#include <errno.h>
#include <stdint.h>

#include "../../../../sys/amd64/vmm/x86_cpuid.c"

ATF_TC_WITHOUT_HEAD(guest_feature_policy_matches_linear_width);
ATF_TC_BODY(guest_feature_policy_matches_linear_width, tc)
{
	uint32_t guest;

	guest = x86_cpuid_guest_stdext2(CPUID_STDEXT2_LA57 |
	    CPUID_STDEXT2_VAES | UINT32_C(0x80000000));
	ATF_CHECK_EQ(guest, CPUID_STDEXT2_VAES);
	ATF_CHECK_EQ(x86_cpuid_linear_address_width(guest), 48);
	ATF_CHECK_EQ(x86_cpuid_linear_address_width(CPUID_STDEXT2_LA57), 57);
}

ATF_TC_WITHOUT_HEAD(v2_virtual_topology);
ATF_TC_BODY(v2_virtual_topology, tc)
{
	uint32_t values[4];

	ATF_REQUIRE_EQ(x86_cpuid_topology(UINT32_C(0x1f), 0, 4, 2, 7,
	    false, values), 0);
	ATF_CHECK_EQ(values[0], UINT32_C(1));
	ATF_CHECK_EQ(values[1], UINT32_C(2));
	ATF_CHECK_EQ(values[2], UINT32_C(0x100));
	ATF_CHECK_EQ(values[3], UINT32_C(7));

	ATF_REQUIRE_EQ(x86_cpuid_topology(UINT32_C(0x1f), 1, 4, 2, 7,
	    false, values), 0);
	ATF_CHECK_EQ(values[0], UINT32_C(3));
	ATF_CHECK_EQ(values[1], UINT32_C(8));
	ATF_CHECK_EQ(values[2], UINT32_C(0x201));
	ATF_CHECK_EQ(values[3], UINT32_C(7));

	ATF_REQUIRE_EQ(x86_cpuid_topology(UINT32_C(0x1f), 2, 4, 2, 7,
	    false, values), 0);
	ATF_CHECK_EQ(values[0], UINT32_C(0));
	ATF_CHECK_EQ(values[1], UINT32_C(0));
	ATF_CHECK_EQ(values[2], UINT32_C(2));
	ATF_CHECK_EQ(values[3], UINT32_C(0));
}

ATF_TC_WITHOUT_HEAD(legacy_availability_and_width);
ATF_TC_BODY(legacy_availability_and_width, tc)
{
	uint32_t values[4];

	ATF_REQUIRE_EQ(x86_cpuid_topology(UINT32_C(0x0b), 0, 2, 3, 5,
	    true, values), 0);
	ATF_CHECK_EQ(values[0], UINT32_C(2));
	ATF_CHECK_EQ(values[1], UINT32_C(3));
	ATF_CHECK_EQ(values[2], UINT32_C(0x100));
	ATF_CHECK_EQ(values[3], UINT32_C(5));
	ATF_REQUIRE_EQ(x86_cpuid_topology(UINT32_C(0x0b), 1, 2, 3, 5,
	    true, values), 0);
	ATF_CHECK_EQ(values[0], UINT32_C(3));
	ATF_CHECK_EQ(values[1], UINT32_C(6));

	ATF_REQUIRE_EQ(x86_cpuid_topology(UINT32_C(0x0b), 0, 2, 3, 5,
	    false, values), 0);
	ATF_CHECK_EQ(values[0], UINT32_C(0));
	ATF_CHECK_EQ(values[1], UINT32_C(0));
	ATF_CHECK_EQ(values[2], UINT32_C(0));
	ATF_CHECK_EQ(values[3], UINT32_C(0));
}

ATF_TC_WITHOUT_HEAD(invalid_inputs_are_transactional);
ATF_TC_BODY(invalid_inputs_are_transactional, tc)
{
	uint32_t values[4] = { 1, 2, 3, 4 };

	ATF_CHECK_EQ(x86_cpuid_topology(UINT32_C(0x1e), 0, 1, 1, 0,
	    true, values), EINVAL);
	ATF_CHECK_EQ(values[0], UINT32_C(1));
	ATF_CHECK_EQ(values[1], UINT32_C(2));
	ATF_CHECK_EQ(values[2], UINT32_C(3));
	ATF_CHECK_EQ(values[3], UINT32_C(4));
	ATF_CHECK_EQ(x86_cpuid_topology(UINT32_C(0x1f), 0, 0, 1, 0,
	    true, values), EINVAL);
	ATF_CHECK_EQ(x86_cpuid_topology(UINT32_C(0x1f), 0, 1, 0, 0,
	    true, values), EINVAL);
	ATF_CHECK_EQ(x86_cpuid_topology(UINT32_C(0x1f), 0, 1, 1, 0,
	    true, NULL), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, guest_feature_policy_matches_linear_width);

	ATF_TP_ADD_TC(tp, v2_virtual_topology);
	ATF_TP_ADD_TC(tp, legacy_availability_and_width);
	ATF_TP_ADD_TC(tp, invalid_inputs_are_transactional);
	return (atf_no_error());
}
