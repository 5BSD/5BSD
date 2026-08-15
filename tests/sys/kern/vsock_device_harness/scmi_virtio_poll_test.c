/* Regression tests for the SCMI VirtIO bounded polling policy. */
#include <sys/types.h>

#include <stdbool.h>

#include <atf-c.h>

#include <dev/firmware/arm/scmi_virtio_poll.h>

ATF_TC_WITHOUT_HEAD(timeout_rounding);
ATF_TC_BODY(timeout_rounding, tc)
{

	ATF_REQUIRE_EQ(0U, scmi_virtio_poll_probes(0));
	ATF_REQUIRE_EQ(1U, scmi_virtio_poll_probes(1));
	ATF_REQUIRE_EQ(1U, scmi_virtio_poll_probes(2));
	ATF_REQUIRE_EQ(2U, scmi_virtio_poll_probes(3));
	ATF_REQUIRE_EQ(2U, scmi_virtio_poll_probes(4));
}

ATF_TC_WITHOUT_HEAD(final_probe_completion);
ATF_TC_BODY(final_probe_completion, tc)
{

	/* Completion, including on the final probe, controls the result. */
	ATF_REQUIRE(scmi_virtio_poll_timed_out(0));
	ATF_REQUIRE(!scmi_virtio_poll_timed_out(1));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, timeout_rounding);
	ATF_TP_ADD_TC(tp, final_probe_completion);
	return (atf_no_error());
}
