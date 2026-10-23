/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <errno.h>

#include "../../../../usr.sbin/bhyve/net_utils.c"

int raw_stdio;

ATF_TC_WITHOUT_HEAD(mtu_parser_rejects_empty_and_out_of_range);
ATF_TC_BODY(mtu_parser_rejects_empty_and_out_of_range, tc)
{
	unsigned long mtu;

	mtu = 42;
	ATF_CHECK_EQ(net_parsemtu("", &mtu), EINVAL);
	ATF_CHECK_EQ(net_parsemtu(" ", &mtu), EINVAL);
	ATF_CHECK_EQ(net_parsemtu("0", &mtu), EINVAL);
	ATF_CHECK_EQ(net_parsemtu("-1", &mtu), EINVAL);
	ATF_CHECK_EQ(net_parsemtu("15x", &mtu), EINVAL);
	ATF_CHECK_EQ(net_parsemtu(NULL, &mtu), EINVAL);
	ATF_CHECK_EQ(net_parsemtu("1500", NULL), EINVAL);
	ATF_CHECK_EQ(mtu, 42);

	errno = EINVAL;
	ATF_CHECK_EQ(net_parsemtu("1500", &mtu), 0);
	ATF_CHECK_EQ(mtu, 1500);
	mtu = 42;
	ATF_CHECK_EQ(net_parsemtu("999999999999999999999999999999999999",
	    &mtu), ERANGE);
	ATF_CHECK_EQ(mtu, 42);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, mtu_parser_rejects_empty_and_out_of_range);
	return (atf_no_error());
}
