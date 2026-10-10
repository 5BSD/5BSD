/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <stddef.h>
#include <netinet/ip_dn_flow.h>
#include <atf-c.h>

ATF_TC(flow_layout);
ATF_TC_HEAD(flow_layout, tc)
{
	atf_tc_set_md_var(tc, "descr", "Extracted Dummynet flow preserves its public ABI");
}
ATF_TC_BODY(flow_layout, tc)
{
	ATF_CHECK_EQ(56, sizeof(struct ipfw_flow_id));
	ATF_CHECK_EQ(0, offsetof(struct ipfw_flow_id, dst_ip));
	ATF_CHECK_EQ(4, offsetof(struct ipfw_flow_id, src_ip));
	ATF_CHECK_EQ(8, offsetof(struct ipfw_flow_id, dst_port));
	ATF_CHECK_EQ(10, offsetof(struct ipfw_flow_id, src_port));
	ATF_CHECK_EQ(12, offsetof(struct ipfw_flow_id, fib));
	ATF_CHECK_EQ(13, offsetof(struct ipfw_flow_id, proto));
	ATF_CHECK_EQ(14, offsetof(struct ipfw_flow_id, _flags));
	ATF_CHECK_EQ(15, offsetof(struct ipfw_flow_id, addr_type));
	ATF_CHECK_EQ(16, offsetof(struct ipfw_flow_id, dst_ip6));
	ATF_CHECK_EQ(32, offsetof(struct ipfw_flow_id, src_ip6));
	ATF_CHECK_EQ(48, offsetof(struct ipfw_flow_id, flow_id6));
	ATF_CHECK_EQ(52, offsetof(struct ipfw_flow_id, extra));
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, flow_layout);
	return (atf_no_error());
}
