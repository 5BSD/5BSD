/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <stdbool.h>

#include "lib9p_impl.h"

ATF_TC_WITHOUT_HEAD(single_component_validation);
ATF_TC_BODY(single_component_validation, tc)
{

	ATF_CHECK(l9p_valid_component("child"));
	ATF_CHECK(l9p_valid_component("child with spaces"));
	ATF_CHECK(l9p_valid_component(".hidden"));
	ATF_CHECK(!l9p_valid_component(NULL));
	ATF_CHECK(!l9p_valid_component(""));
	ATF_CHECK(!l9p_valid_component("."));
	ATF_CHECK(!l9p_valid_component(".."));
	ATF_CHECK(!l9p_valid_component("nested/child"));
	ATF_CHECK(!l9p_valid_component("/absolute"));
	ATF_CHECK(!l9p_valid_component("trailing/"));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, single_component_validation);
	return (atf_no_error());
}
