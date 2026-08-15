/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>

#include "tpm_intf_crb_model.h"

ATF_TC_WITHOUT_HEAD(subword_write_decode);
ATF_TC_BODY(subword_write_decode, tc)
{
	uint32_t decoded;

	(void)tc;
	ATF_REQUIRE_EQ(tpm_crb_control_write_decode(0x1234, 0, 1,
	    &decoded), 0);
	ATF_CHECK_EQ(decoded, 0x34);
	ATF_REQUIRE_EQ(tpm_crb_control_write_decode(0x1234, 1, 1,
	    &decoded), 0);
	ATF_CHECK_EQ(decoded, 0x3400);
	ATF_REQUIRE_EQ(tpm_crb_control_write_decode(0x12345678, 2, 2,
	    &decoded), 0);
	ATF_CHECK_EQ(decoded, 0x56780000);
	ATF_REQUIRE_EQ(tpm_crb_control_write_decode(UINT64_MAX, 0, 4,
	    &decoded), 0);
	ATF_CHECK_EQ(decoded, UINT32_MAX);
}

ATF_TC_WITHOUT_HEAD(invalid_subword_write_is_atomic);
ATF_TC_BODY(invalid_subword_write_is_atomic, tc)
{
	uint32_t decoded;

	(void)tc;
	decoded = 0xa5a5a5a5;
	ATF_CHECK_EQ(tpm_crb_control_write_decode(1, 1, 2, &decoded), EINVAL);
	ATF_CHECK_EQ(decoded, 0xa5a5a5a5);
	ATF_CHECK_EQ(tpm_crb_control_write_decode(1, 3, 2, &decoded), EINVAL);
	ATF_CHECK_EQ(decoded, 0xa5a5a5a5);
	ATF_CHECK_EQ(tpm_crb_control_write_decode(1, 0, 8, &decoded), EINVAL);
	ATF_CHECK_EQ(decoded, 0xa5a5a5a5);
	ATF_CHECK_EQ(tpm_crb_control_write_decode(1, 0, 1, NULL), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, subword_write_decode);
	ATF_TP_ADD_TC(tp, invalid_subword_write_is_atomic);
	return (atf_no_error());
}
