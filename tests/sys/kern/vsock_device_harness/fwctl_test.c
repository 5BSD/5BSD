#include <sys/endian.h>

#include <errno.h>
#include <stdint.h>

#include <atf-c.h>

extern int guest_ncpus;
int guest_ncpus = 2;

#include "fwctl.c"

int
register_inout(struct inout_port *iop __unused)
{

	return (0);
}

ATF_TC_WITHOUT_HEAD(short_request_returns_error);
ATF_TC_BODY(short_request_returns_error, tc)
{
	uint32_t word;

	fwctl_init();
	ATF_CHECK_EQ(fwctl_request(8), 0);
	ATF_CHECK_EQ(fwctl_request(OP_GET), 0);
	ATF_CHECK_EQ(fwctl_request(0x1234), 1);
	ATF_CHECK_EQ(rinfo.resp_error, EINVAL);
	ATF_CHECK_EQ(fwctl_response(&word), 0);
	ATF_CHECK_EQ(word, 4 * sizeof(uint32_t));
	ATF_CHECK_EQ(fwctl_response(&word), 0);
	ATF_CHECK_EQ(word, OP_GET);
	ATF_CHECK_EQ(fwctl_response(&word), 0);
	ATF_CHECK_EQ(word, 0x1234);
	ATF_CHECK_EQ(fwctl_response(&word), 1);
	ATF_CHECK_EQ(word, EINVAL);
}

ATF_TC_WITHOUT_HEAD(unaligned_payload_waits_for_last_word);
ATF_TC_BODY(unaligned_payload_waits_for_last_word, tc)
{
	const uint8_t first[4] = { 'h', 'w', '.', 'n' };
	const uint8_t last[4] = { 'c', 'p', 'u', 0 };

	fwctl_init();
	ATF_CHECK_EQ(fwctl_request(12 + 7), 0);
	ATF_CHECK_EQ(fwctl_request(OP_GET), 0);
	ATF_CHECK_EQ(fwctl_request(0x5678), 0);
	ATF_CHECK_EQ(fwctl_request(le32dec(first)), 0);
	ATF_CHECK_EQ(rinfo.req_size, 3);
	ATF_CHECK_EQ(fwctl_request(le32dec(last)), 1);
	ATF_CHECK_EQ(rinfo.req_size, 0);
	ATF_CHECK_EQ(rinfo.resp_error, 0);
	ATF_CHECK_EQ(rinfo.resp_size, sizeof(size_t) + sizeof(guest_ncpus));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, short_request_returns_error);
	ATF_TP_ADD_TC(tp, unaligned_payload_waits_for_last_word);
	return (atf_no_error());
}
